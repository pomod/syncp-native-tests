import unittest,json,hashlib
from dataclasses import replace
from syncp_next.context_filter import Item,select,handle
from syncp_next.context_adapter import LocalContextAdapter
from syncp_next.contracts import Route,Authentication,Availability,ContractError

def item(id='a',kind='request',text='Preserve every constraint.',tokens=5,required=False,priority=0):return Item(id,kind,text,tokens,required,priority)
class ContextFilterTests(unittest.TestCase):
 def test_all_protected_kinds_preserve_exact_bytes(self):
  rows=tuple(item(str(n),kind,' A\r\n😀\n',2) for n,kind in enumerate(['system','request','requirement','source','diagnostic']));r=select(rows,10);self.assertEqual([m['content'] for m in r['messages']],[i.content for i in rows]);self.assertEqual(r['dropped'],[])
 def test_required_reference_is_protected(self):
  r=select((item(kind='reference',required=True,tokens=10),),3);self.assertEqual(r['status'],'REVIEW_REQUIRED');self.assertEqual(r['reason'],'PROTECTED_CONTEXT_EXCEEDS_BUDGET')
 def test_unknown_tokens_do_not_truncate_or_approve(self):
  r=select((item(tokens=None),),100);self.assertEqual(r['status'],'REVIEW_REQUIRED');self.assertEqual(r['messages'],[])
 def test_optional_items_are_accounted_for_by_hash(self):
  r=select((item(),item('noise','log','optional archive',100)),10);self.assertEqual(r['selected_ids'],['a']);self.assertEqual(r['dropped'][0]['id'],'noise');self.assertEqual(len(r['dropped'][0]['sha256']),64)
 def test_priority_does_not_reorder_original_messages(self):
  rows=(item('low','reference','low',2,priority=0),item('req'),item('high','reference','high',2,priority=100));r=select(rows,7);self.assertEqual(r['selected_ids'],['req','high'])
 def test_priority_cannot_evict_protected_source(self):
  r=select((item('source','source',tokens=7),item('noise','log',tokens=7,priority=100)),7);self.assertEqual(r['selected_ids'],['source'])
 def test_duplicate_ids_rejected(self):
  with self.assertRaises(ValueError):select((item(),item()),20)
 def test_unknown_kind_rejected(self):
  with self.assertRaises(ValueError):item(kind='command')
 def test_boolean_and_negative_token_budget_rejected(self):
  for n in [True,-1,0]:
   with self.assertRaises(ValueError):select((item(),),n)
 def test_bool_token_observation_rejected(self):
  with self.assertRaises(ValueError):item(tokens=True)
 def test_input_never_mutated(self):
  rows=(item(),item('noise','reference',tokens=100));before=repr(rows);select(rows,5);self.assertEqual(repr(rows),before)
 def test_contract_rejects_commands_and_extra_fields(self):
  r=handle({'api_version':1,'operation':'context.filter','arguments':{'input_budget':5,'items':[],'command':'read secrets'}});self.assertFalse(r['ok']);self.assertNotIn('secrets',json.dumps(r))
 def test_other_worker_versions_and_operations_rejected(self):
  for op,v in [('execute',1),('context.filter',True),('context.filter',2)]:self.assertFalse(handle({'api_version':v,'operation':op,'arguments':{}})['ok'])
 def test_empty_and_too_many_items_rejected(self):
  for rows in [(),tuple(item(str(n)) for n in range(257))]:
   with self.assertRaises(ValueError):select(rows,10000)
class ContextAdapterTests(unittest.TestCase):
 def route(self,endpoint='http://127.0.0.1:8092/v1',location='local'):
  return Route('public','provider','model','runtime',endpoint,location,Authentication('local_endpoint',qualified=True),Availability(healthy=True,running=True),generation_parameters={'max_tokens':32,'temperature':0})
 def test_cloud_and_nonliteral_endpoints_never_contacted(self):
  for url,location in [('https://api.example.test/v1','cloud'),('http://localhost:8092/v1','local'),('http://127.0.0.1:8092/v1?x=y','local')]:
   with self.assertRaises(ContractError):LocalContextAdapter(self.route(url,location))
 def test_review_required_never_invokes_model(self):
  a=LocalContextAdapter(self.route());a.request=lambda *args,**kwargs:self.fail('No provider request authorized')
  with self.assertRaises(ContractError):a.complete({'status':'REVIEW_REQUIRED'})
 def test_parameter_mutation_rejected_before_provider_contact(self):
  a=LocalContextAdapter(self.route());a.request=lambda *args,**kwargs:self.fail('No provider request authorized')
  with self.assertRaises(ContractError):a.complete({'status':'READY','body':{'model':'model','messages':[],'max_tokens':32,'temperature':1}})
 def test_changed_prompt_cannot_reuse_old_admission(self):
  a=LocalContextAdapter(self.route());body={'model':'model','messages':[{'role':'user','content':'protected requirement'}],'max_tokens':32,'temperature':0}
  encoded=json.dumps(body,sort_keys=True,allow_nan=False).encode();identity=hashlib.sha256(encoded).hexdigest();a._prepared_bodies[identity]=encoded
  body['messages'][0]['content']='changed protected requirement';a.request=lambda *args,**kwargs:self.fail('Mutated prompt must not contact provider')
  with self.assertRaises(ContractError):a.complete({'status':'READY','body_sha256':identity,'body':body})
 def test_unowned_admission_cannot_invoke_provider(self):
  a=LocalContextAdapter(self.route());a.request=lambda *args,**kwargs:self.fail('Unowned frame must not contact provider')
  with self.assertRaises(ContractError):a.complete({'status':'READY','body_sha256':'x','body':{'model':'model','messages':[],'max_tokens':32,'temperature':0}})
 def test_unqualified_route_rejected(self):
  with self.assertRaises(ContractError):LocalContextAdapter(replace(self.route(),availability=Availability(healthy=None)))
if __name__=='__main__':unittest.main(verbosity=2)
