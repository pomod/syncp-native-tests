from dataclasses import replace
from pathlib import Path
import unittest
from syncp_next.contracts import Authentication, Availability, ContractError, Route, SelectionPolicy, select_route
from syncp_next.discovery import parse_linux_memory, parse_nvidia_csv
from syncp_next.worker import handle


def route(id="local", location="local", **changes):
    base = Route(id, "vendor", "model-a", "runtime-a", "http://127.0.0.1:8092/v1" if location == "local" else "https://api.example.test/v1",
                 location, Authentication("local_endpoint" if location == "local" else "official_cli", qualified=True),
                 Availability(configured=True, healthy=True, running=True, failed=False),
                 capabilities=frozenset({"text"}), generation_parameters={"temperature": 0.1},
                 system_instructions=("Preserve the project constraints",), may_incur_cost=location == "cloud")
    return replace(base, **changes)


class AuthorityTests(unittest.TestCase):
    def test_explicit_local_selection_preserves_parameters_and_instructions(self):
        local = route()
        self.assertIs(select_route("LOCAL", (local,), SelectionPolicy(frozenset({"local"})), selected_id="local"), local)

    def test_explicit_cloud_does_not_fallback(self):
        policy = SelectionPolicy(frozenset({"local", "cloud"}), ("local", "cloud"), frozenset({"cloud"}))
        with self.assertRaisesRegex(ContractError, "readiness"):
            select_route("CLOUD", (route(), route("cloud", "cloud", availability=Availability(configured=True))), policy, selected_id="cloud")

    def test_auto_unknown_cost_requires_spending_authority(self):
        cloud = route("cloud", "cloud", may_incur_cost=None)
        with self.assertRaisesRegex(ContractError, "spending"):
            select_route("AUTO", (cloud,), SelectionPolicy(frozenset({"cloud"}), ("cloud",)))

    def test_auto_respects_approved_order(self):
        local, cloud = route(), route("cloud", "cloud")
        policy = SelectionPolicy(frozenset({"local", "cloud"}), ("cloud", "local"))
        self.assertIs(select_route("AUTO", (local, cloud), policy), local)

    def test_private_cloud_context_has_separate_authority(self):
        cloud = route("cloud", "cloud")
        policy = SelectionPolicy(frozenset({"cloud"}), (), frozenset({"cloud"}))
        with self.assertRaisesRegex(ContractError, "private context"):
            select_route("CLOUD", (cloud,), policy, selected_id="cloud", private_context=True)
        approved = replace(policy, cloud_context_authorized_route_ids=frozenset({"cloud"}))
        self.assertIs(select_route("CLOUD", (cloud,), approved, selected_id="cloud", private_context=True), cloud)

    def test_local_never_routes_to_cloud_even_with_spending_approval(self):
        with self.assertRaisesRegex(ContractError, "LOCAL"):
            select_route("LOCAL", (route("cloud", "cloud"),), SelectionPolicy(frozenset({"cloud"}), cost_authorized_route_ids=frozenset({"cloud"})), selected_id="cloud")

    def test_unapproved_and_unqualified_routes_fail(self):
        with self.assertRaisesRegex(ContractError, "approved"):
            select_route("LOCAL", (route(),), SelectionPolicy(frozenset()), selected_id="local")
        with self.assertRaisesRegex(ContractError, "Authentication"):
            select_route("CLOUD", (route("cloud", "cloud", authentication=Authentication("subscription_cli")),), SelectionPolicy(frozenset({"cloud"})), selected_id="cloud")

    def test_duplicate_routes_and_candidates_rejected(self):
        with self.assertRaisesRegex(ContractError, "Duplicate route"):
            select_route("AUTO", (route(), route()), SelectionPolicy(frozenset({"local"}), ("local",)))
        with self.assertRaisesRegex(ContractError, "Duplicate AUTO"):
            select_route("AUTO", (route(),), SelectionPolicy(frozenset({"local"}), ("local", "local")))

    def test_capabilities_not_assumed(self):
        with self.assertRaisesRegex(ContractError, "capabilities"):
            select_route("LOCAL", (route(),), SelectionPolicy(frozenset({"local"})), selected_id="local", required_capabilities=frozenset({"tool_calling"}))

    def test_endpoint_secrets_and_network_local_route_rejected(self):
        for endpoint in ("https://name:secret@example.test", "https://example.test?key=secret", "http://192.168.1.2:8092"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ContractError):
                route(endpoint=endpoint)

    def test_password_and_nonfinite_parameters_rejected(self):
        with self.assertRaises(ContractError):
            Authentication("password")
        with self.assertRaises(ContractError):
            Authentication("api_key_reference", "secret")
        with self.assertRaises(ContractError):
            route(generation_parameters={"temperature": float("nan")})

    def test_approved_parameters_cannot_mutate_after_selection(self):
        parameters = {"temperature": 0.2}
        approved = route(generation_parameters=parameters)
        parameters["temperature"] = 2
        self.assertEqual(approved.generation_parameters["temperature"], 0.2)
        with self.assertRaises(TypeError):
            approved.generation_parameters["temperature"] = 2

    def test_malformed_endpoint_cost_and_auth_types_rejected(self):
        with self.assertRaises(ContractError):
            route(endpoint="http://[malformed")
        with self.assertRaises(ContractError):
            route(may_incur_cost="false")
        with self.assertRaises(ContractError):
            Authentication("official_cli", qualified="true")

    def test_state_contradictions_not_hidden(self):
        with self.assertRaises(ContractError):
            Availability(running=False, healthy=True)
        with self.assertRaises(ContractError):
            Availability(installed="true")


class DiscoveryTests(unittest.TestCase):
    def test_memory_unknown_is_not_zero(self):
        self.assertEqual(parse_linux_memory("MemTotal: 32 kB"), {"total_bytes": 32768, "available_bytes": None})

    def test_gpu_free_memory_and_unknown_values(self):
        devices = parse_nvidia_csv('"Other GPU", 8192, 512, 600.0, gpu-1\nGPU 2, N/A, N/A, 600.0, gpu-2')
        self.assertEqual(devices[0]["available_vram_bytes"], 512 * 1024**2)
        self.assertIsNone(devices[1]["available_vram_bytes"])
        self.assertFalse(devices[0]["inference_backend_qualified"])

    def test_impossible_gpu_observations_rejected(self):
        self.assertEqual(parse_nvidia_csv("GPU, 512, 8192, x, y"), [])

    def test_worker_unknown_operations_and_versions_do_not_execute(self):
        for request in ({"api_version": 2, "operation": "hardware.discover", "arguments": {}},
                        {"api_version": 1, "operation": "shell", "arguments": {"command": "anything"}},
                        {"api_version": True, "operation": "hardware.discover", "arguments": {}}, {}):
            with self.subTest(request=request):
                self.assertFalse(handle(request)["ok"])

    def test_worker_does_not_accept_relative_paths_or_extra_arguments(self):
        self.assertFalse(handle({"api_version": 1, "operation": "hardware.discover", "arguments": {"disk_path": "relative"}})["ok"])
        self.assertFalse(handle({"api_version": 1, "operation": "hardware.discover", "arguments": {"disk_path": str(Path.cwd()), "shell": "anything"}})["ok"])


if __name__ == "__main__":
    unittest.main()
