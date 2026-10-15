"""Versioned, conservative context selection; no provider call or execution authority.

Only explicitly optional reference/log items may be dropped. System instructions,
requests, requirements, source and diagnostics retain their original bytes/order.
Unknown token counts or an over-budget protected set require review, never truncation.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import sys

VERSION=1
MAX_REQUEST_BYTES=262144
PROTECTED_KINDS=frozenset({'system','request','requirement','source','diagnostic'})
KINDS=PROTECTED_KINDS|{'reference','log'}
class FilterError(ValueError):pass

def integer(value,low,high,label):
    if type(value) is not int or not low<=value<=high:raise FilterError(label)
    return value

@dataclass(frozen=True)
class Item:
    id:str
    kind:str
    content:str
    tokens:int|None
    required:bool
    priority:int
    def __post_init__(self):
        if not isinstance(self.id,str) or not 1<=len(self.id)<=128 or any(c in self.id for c in '\n\r\t'):raise FilterError('INVALID_ITEM_ID')
        if self.kind not in KINDS:raise FilterError('UNKNOWN_CONTEXT_KIND')
        if not isinstance(self.content,str) or len(self.content.encode('utf8'))>MAX_REQUEST_BYTES:raise FilterError('INVALID_CONTEXT_CONTENT')
        if self.tokens is not None:integer(self.tokens,0,131072,'INVALID_TOKEN_OBSERVATION')
        if type(self.required) is not bool:raise FilterError('INVALID_REQUIRED_FLAG')
        integer(self.priority,0,100,'INVALID_PRIORITY')
    @property
    def protected(self):return self.required or self.kind in PROTECTED_KINDS
    @property
    def sha256(self):return hashlib.sha256(self.content.encode('utf8')).hexdigest()

def select(items:tuple[Item,...],input_budget:int)->dict:
    integer(input_budget,1,131072,'INVALID_INPUT_BUDGET')
    if not 1<=len(items)<=256 or len({i.id for i in items})!=len(items):raise FilterError('INVALID_OR_DUPLICATE_ITEMS')
    protected=[i for i in items if i.protected]
    unknown=[i.id for i in items if i.tokens is None]
    common={'api_version':VERSION,'input_budget':input_budget,'protected_ids':[i.id for i in protected],'protected_content_hashes':{i.id:i.sha256 for i in protected},'original_order':[i.id for i in items],'token_measurement':'caller-supplied observed item counts; adapter must remeasure rendered prompt'}
    if unknown:return dict(common,status='REVIEW_REQUIRED',reason='TOKEN_COUNTS_UNKNOWN',unknown_ids=unknown,selected_ids=[],dropped=[],messages=[])
    protected_tokens=sum(i.tokens for i in protected)
    if protected_tokens>input_budget:return dict(common,status='REVIEW_REQUIRED',reason='PROTECTED_CONTEXT_EXCEEDS_BUDGET',protected_tokens=protected_tokens,selected_ids=[],dropped=[],messages=[])
    selected={i.id for i in protected};used=protected_tokens
    # Priority influences optional inclusion only; output retains original order.
    optional=sorted((i for i in items if not i.protected),key=lambda i:(-i.priority,next(n for n,x in enumerate(items) if x.id==i.id)))
    for i in optional:
        if used+i.tokens<=input_budget:selected.add(i.id);used+=i.tokens
    kept=[i for i in items if i.id in selected]
    return dict(common,status='READY_FOR_ADAPTER_VERIFICATION',observed_item_tokens=used,original_item_tokens=sum(i.tokens for i in items),selected_ids=[i.id for i in kept],dropped=[{'id':i.id,'kind':i.kind,'sha256':i.sha256,'tokens':i.tokens,'reason':'explicitly optional context does not fit reviewed input budget'} for i in items if i.id not in selected],messages=[{'id':i.id,'kind':i.kind,'content':i.content,'sha256':i.sha256} for i in kept])

def handle(request:object)->dict:
    try:
        if not isinstance(request,dict) or set(request)!={'api_version','operation','arguments'}:raise FilterError('INVALID_FILTER_ENVELOPE')
        if type(request['api_version']) is not int or request['api_version']!=VERSION:raise FilterError('UNSUPPORTED_FILTER_VERSION')
        if request['operation']!='context.filter':raise FilterError('UNSUPPORTED_FILTER_OPERATION')
        args=request['arguments']
        if not isinstance(args,dict) or set(args)!={'items','input_budget'} or not isinstance(args['items'],list):raise FilterError('INVALID_FILTER_ARGUMENTS')
        items=[]
        for row in args['items']:
            if not isinstance(row,dict) or set(row)!={'id','kind','content','tokens','required','priority'}:raise FilterError('INVALID_FILTER_ITEM')
            items.append(Item(**row))
        return {'api_version':VERSION,'ok':True,'result':select(tuple(items),args['input_budget'])}
    except (FilterError,TypeError,UnicodeError) as e:
        # Report only fixed contract labels, not rejected content, paths or keys.
        return {'api_version':VERSION,'ok':False,'error':str(e) if isinstance(e,FilterError) else 'INVALID_FILTER_TYPES'}

def main()->int:
    raw=sys.stdin.buffer.read(MAX_REQUEST_BYTES+1)
    try:result=handle(json.loads(raw)) if len(raw)<=MAX_REQUEST_BYTES else {'api_version':VERSION,'ok':False,'error':'FILTER_REQUEST_TOO_LARGE'}
    except (ValueError,UnicodeError):result={'api_version':VERSION,'ok':False,'error':'INVALID_FILTER_JSON'}
    print(json.dumps(result,ensure_ascii=False,allow_nan=False));return 0 if result['ok'] else 2
if __name__=='__main__':raise SystemExit(main())
