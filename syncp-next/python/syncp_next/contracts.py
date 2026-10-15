"""Version-one contracts. Selection validates authority; it never executes work."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
from types import MappingProxyType
from urllib.parse import urlsplit
import ipaddress
import math
import re

API_VERSION = 1
Mode = Literal["LOCAL", "CLOUD", "AUTO"]


class ContractError(ValueError):
    """An actionable, credential-free contract rejection."""


def _identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@+ -]{0,255}", value):
        raise ContractError(f"Invalid {label}")


@dataclass(frozen=True)
class Availability:
    installed: bool | None = None
    configured: bool | None = None
    running: bool | None = None
    healthy: bool | None = None
    failed: bool | None = None
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("installed", "configured", "running", "healthy", "failed"):
            if getattr(self, name) is not None and type(getattr(self, name)) is not bool:
                raise ContractError(f"{name} must be boolean or unknown")
        if self.healthy is True and (self.failed is True or self.running is False):
            raise ContractError("Health contradicts the observed process state")


@dataclass(frozen=True)
class Authentication:
    method: Literal["none", "api_key_reference", "official_cli", "subscription_cli", "local_endpoint"]
    credential_reference: str | None = field(default=None, repr=False)
    qualified: bool = False

    def __post_init__(self) -> None:
        if type(self.qualified) is not bool:
            raise ContractError("Authentication qualification must be boolean")
        if self.method not in {"none", "api_key_reference", "official_cli", "subscription_cli", "local_endpoint"}:
            raise ContractError("Unsupported authentication method")
        if self.credential_reference is not None:
            # This is an opaque reference, never a secret value or a password.
            if not self.credential_reference.startswith("os-secret:"):
                raise ContractError("Use an OS-protected credential reference")
            _identifier(self.credential_reference, "credential reference")
        if self.method == "api_key_reference" and not self.credential_reference:
            raise ContractError("API key authentication requires a credential reference")


@dataclass(frozen=True)
class Route:
    id: str
    provider: str
    model: str
    runtime: str
    endpoint: str
    location: Literal["local", "cloud"]
    authentication: Authentication
    availability: Availability
    capabilities: frozenset[str] = frozenset()
    generation_parameters: dict[str, Any] = field(default_factory=dict)
    system_instructions: tuple[str, ...] = ()
    tool_permissions: frozenset[str] = frozenset()
    resource_requirements: dict[str, int | None] = field(default_factory=dict)
    may_incur_cost: bool | None = None

    def __post_init__(self) -> None:
        for name in ("id", "provider", "model", "runtime"):
            _identifier(getattr(self, name), name)
        if self.location not in {"local", "cloud"}:
            raise ContractError("Unsupported route location")
        try:
            endpoint = urlsplit(self.endpoint)
            endpoint.port
        except (ValueError, TypeError):
            raise ContractError("Invalid endpoint") from None
        if endpoint.scheme not in {"http", "https"} or not endpoint.hostname:
            raise ContractError("An explicit HTTP endpoint is required")
        if endpoint.username or endpoint.password or endpoint.fragment or endpoint.query:
            raise ContractError("Endpoint must not contain credentials, queries or fragments")
        if self.location == "local":
            try:
                loopback = ipaddress.ip_address(endpoint.hostname).is_loopback
            except ValueError:
                loopback = endpoint.hostname.lower() == "localhost"
            if not loopback:
                raise ContractError("Version one local routes require a loopback endpoint")
        elif endpoint.scheme != "https":
            raise ContractError("Cloud routes require HTTPS")
        for value in self.generation_parameters.values():
            if not isinstance(value, (str, bool, int, float, type(None))):
                raise ContractError("Generation parameters must be scalar values")
            if isinstance(value, float) and not math.isfinite(value):
                raise ContractError("Generation parameters must be finite")
        for value in self.resource_requirements.values():
            if value is not None and (type(value) is not int or value < 0):
                raise ContractError("Resource requirements must be non-negative bytes or unknown")
        if self.may_incur_cost is not None and type(self.may_incur_cost) is not bool:
            raise ContractError("Cost possibility must be boolean or unknown")
        # Selection must not observe silently mutated effective parameters after approval.
        object.__setattr__(self, "generation_parameters", MappingProxyType(dict(self.generation_parameters)))
        object.__setattr__(self, "resource_requirements", MappingProxyType(dict(self.resource_requirements)))
        object.__setattr__(self, "system_instructions", tuple(self.system_instructions))
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        object.__setattr__(self, "tool_permissions", frozenset(self.tool_permissions))


@dataclass(frozen=True)
class SelectionPolicy:
    approved_route_ids: frozenset[str]
    auto_order: tuple[str, ...] = ()
    cost_authorized_route_ids: frozenset[str] = frozenset()
    cloud_context_authorized_route_ids: frozenset[str] = frozenset()


def select_route(
    mode: Mode,
    routes: tuple[Route, ...],
    policy: SelectionPolicy,
    *,
    selected_id: str | None = None,
    private_context: bool = False,
    required_capabilities: frozenset[str] = frozenset(),
) -> Route:
    """Return one exact route or fail. Unknown availability is not readiness."""
    indexed = {route.id: route for route in routes}
    if len(indexed) != len(routes):
        raise ContractError("Duplicate route IDs")
    if mode not in {"LOCAL", "CLOUD", "AUTO"}:
        raise ContractError("Unsupported operating mode")
    if mode == "AUTO":
        if selected_id is not None:
            raise ContractError("AUTO uses the explicit approved candidate order")
        ids = policy.auto_order
        if len(set(ids)) != len(ids):
            raise ContractError("Duplicate AUTO candidates")
    else:
        if not selected_id:
            raise ContractError("Explicit model selection is required")
        ids = (selected_id,)
    reasons: list[str] = []
    for route_id in ids:
        route = indexed.get(route_id)
        reason = None
        if route is None:
            reason = "Route is not registered"
        elif route_id not in policy.approved_route_ids:
            reason = "Route is not approved"
        elif mode == "LOCAL" and route.location != "local":
            reason = "LOCAL cannot select a cloud route"
        elif mode == "CLOUD" and route.location != "cloud":
            reason = "CLOUD requires the selected cloud route"
        elif route.availability.configured is not True or route.availability.healthy is not True:
            reason = "Route readiness has not been verified"
        elif route.availability.failed is True:
            reason = "Route has an observed failure"
        elif not required_capabilities.issubset(route.capabilities):
            reason = "Route lacks required capabilities"
        elif route.location == "cloud" and not route.authentication.qualified:
            reason = "Authentication method is not qualified"
        elif route.location == "cloud" and route.may_incur_cost is not False and route_id not in policy.cost_authorized_route_ids:
            reason = "Cloud spending is not authorized"
        elif route.location == "cloud" and private_context and route_id not in policy.cloud_context_authorized_route_ids:
            reason = "Cloud access to private context is not authorized"
        if reason:
            reasons.append(f"{route_id}: {reason}")
            continue
        return route
    raise ContractError("No authorized available route. " + "; ".join(reasons))
