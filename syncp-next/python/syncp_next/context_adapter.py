"""One qualified LOCAL llama.cpp/OpenAI-compatible context adapter.

Versioned filtering never grants route authority. The caller supplies its already
selected immutable Route. No cloud endpoint, model fallback, parameter rewrite,
profile change or task deadline is introduced. Token/template probes are diagnostics.
"""
from __future__ import annotations
import json,time,hashlib
from urllib.parse import urlsplit
from urllib.request import Request,urlopen
from .contracts import Route,ContractError
from .context_filter import Item,select

class LocalContextAdapter:
    def __init__(self,route:Route):
        u=urlsplit(route.endpoint)
        if route.location!='local' or u.scheme!='http' or u.hostname!='127.0.0.1' or not u.port or u.username or u.password or u.query or u.fragment or u.path!='/v1':raise ContractError('LOCAL_CONTEXT_ADAPTER_ENDPOINT_NOT_QUALIFIED')
        if route.availability.healthy is not True or route.availability.failed is True or route.authentication.qualified is not True:raise ContractError('LOCAL_CONTEXT_ROUTE_NOT_QUALIFIED')
        if {'model','messages','tools','tool_choice','timeout'}&set(route.generation_parameters):raise ContractError('CONTEXT_ADAPTER_RESERVED_PARAMETER')
        self.route=route;self.base=route.endpoint[:-3];self._prepared_bodies={}
    def request(self,path:str,body=None,*,inference=False):
        headers={'Content-Type':'application/json'};raw=None if body is None else json.dumps(body,allow_nan=False).encode()
        with urlopen(Request(self.base+path,data=raw,headers=headers),timeout=None if inference else 5) as r:
            payload=r.read(2097153)
            if len(payload)>2097152:raise ContractError('OVERSIZED_CONTEXT_ADAPTER_RESPONSE')
            return json.loads(payload)
    def observe(self):
        models=self.request('/v1/models');props=self.request('/props')
        if not any(m.get('id')==self.route.model for m in models.get('data',[])):raise ContractError('SELECTED_CONTEXT_MODEL_UNAVAILABLE')
        context=props.get('default_generation_settings',{}).get('n_ctx')
        if type(context) is not int or context<=0:raise ContractError('RUNTIME_CONTEXT_UNKNOWN')
        return context
    def tokens(self,text:str):
        data=self.request('/tokenize',{'content':text,'add_special':False})
        if not isinstance(data.get('tokens'),list):raise ContractError('TOKENIZER_OBSERVATION_UNAVAILABLE')
        return len(data['tokens'])
    def prepare(self,items:tuple[Item,...],*,filtered:bool,input_budget:int):
        context=self.observe()
        measured=tuple(Item(i.id,i.kind,i.content,self.tokens(i.content),i.required,i.priority) for i in items)
        decision=select(measured,input_budget) if filtered else {'status':'READY_FOR_ADAPTER_VERIFICATION','selected_ids':[i.id for i in measured],'dropped':[],'messages':[{'id':i.id,'kind':i.kind,'content':i.content,'sha256':i.sha256} for i in measured],'protected_content_hashes':{i.id:i.sha256 for i in measured if i.protected}}
        if decision['status']!='READY_FOR_ADAPTER_VERIFICATION':return {'status':'REVIEW_REQUIRED','decision':decision}
        messages=[{'role':'system' if i['kind']=='system' else 'user','content':i['content']} for i in decision['messages']]
        rendered=self.request('/apply-template',{'messages':messages,'add_generation_prompt':True})
        if not isinstance(rendered.get('prompt'),str):raise ContractError('CHAT_TEMPLATE_OBSERVATION_UNAVAILABLE')
        prompt_tokens=self.tokens(rendered['prompt']);output=self.route.generation_parameters.get('max_tokens')
        if type(output) is not int or output<=0:raise ContractError('EXPLICIT_OUTPUT_RESERVE_REQUIRED')
        # Extra reserve is admission headroom, not a wall-clock task deadline.
        if prompt_tokens+output+256>context:return {'status':'REVIEW_REQUIRED','reason':'RENDERED_CONTEXT_EXCEEDS_RUNTIME','prompt_tokens':prompt_tokens,'actual_context':context,'decision':decision}
        body={'model':self.route.model,'messages':messages,**dict(self.route.generation_parameters)}
        encoded=json.dumps(body,sort_keys=True,allow_nan=False).encode();identity=hashlib.sha256(encoded).hexdigest()
        if len(self._prepared_bodies)>=8:self._prepared_bodies.pop(next(iter(self._prepared_bodies)))
        self._prepared_bodies[identity]=encoded
        return {'status':'READY','body_sha256':identity,'body':body,'prompt_tokens_observed':prompt_tokens,'actual_context':context,'decision':decision,'model':self.route.model,'parameters_preserved':dict(self.route.generation_parameters),'task_timeout_seconds':0}
    def complete(self,prepared:dict):
        if prepared.get('status')!='READY':raise ContractError('CONTEXT_REVIEW_REQUIRED_BEFORE_INFERENCE')
        if prepared['body']['model']!=self.route.model or {k:v for k,v in prepared['body'].items() if k not in ['model','messages']}!=dict(self.route.generation_parameters):raise ContractError('PREPARED_ROUTE_PARAMETERS_CHANGED')
        encoded=json.dumps(prepared['body'],sort_keys=True,allow_nan=False).encode()
        if self._prepared_bodies.get(prepared.get('body_sha256'))!=encoded:raise ContractError('PREPARED_CONTEXT_CHANGED_OR_NOT_OWNED')
        started=time.monotonic();response=self.request('/v1/chat/completions',prepared['body'],inference=True);elapsed=time.monotonic()-started
        if response.get('model')!=self.route.model:raise ContractError('CONTEXT_RESPONSE_MODEL_MISMATCH')
        return {'response':response,'elapsed_seconds':elapsed,'usage':response.get('usage',{}),'prompt_tokens_observed':prepared['prompt_tokens_observed'],'task_timeout_seconds':0}
