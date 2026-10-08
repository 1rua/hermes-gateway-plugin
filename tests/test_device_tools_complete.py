"""Real device capability publication, online TTL0 claim and native result adoption."""
import asyncio,hashlib,json,sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway.core import create_gateway_core,VerifiedRequestContext,GatewayError,_jcs
from open_android_intelligence_gateway import device_tools
from test_support import make_secret_store,seed_event_session

def test_native_tool_consumes_only_exact_adopted_result_and_rejects_untrusted_routing(tmp_path):
    core=create_gateway_core(tmp_path,secret_store=make_secret_store())
    seed_event_session(core)
    context=VerifiedRequestContext(account_id='acct_alice',device_id='dev_1',session_id='sess_1',request_id='req_tool',correlation_id='cor_tool',pairing_generation=1,grant_revision=1)
    core.set_device_online(context,True)
    schema={'type':'object','additionalProperties':False,'required':['limit'],'properties':{'limit':{'type':'integer','minimum':1,'maximum':2}}}
    binding={'pluginId':'org.example.actual','authorKeyId':'sha256:'+'a'*64,'capabilityId':'org.example.actual.read','capabilityVersion':'1.0.0','schemaSha256':'sha256:'+hashlib.sha256(_jcs(schema).encode()).hexdigest(),'schema':schema,'risk':'high-privilege-ephemeral'}
    a=core.open_gateway_account('acct_alice')
    try:
        assert a.device_requests.capabilities.list('dev_1',1,1)==[]
        a.device_requests.capabilities.register('dev_1',1,1,[binding])
        with pytest.raises(GatewayError):a.device_requests.capabilities.register('dev_1',1,1,[{**binding,'schemaSha256':'sha256:'+'0'*64}])
    finally:a.close()
    args={'capabilityId':binding['capabilityId'],'capabilityVersion':'1.0.0','parameters':{'limit':1}}
    async def scenario():
        with pytest.raises(GatewayError,match='PAIRING_REQUIRED'): await device_tools.execute(core,args,session_id='native_one')
        origin={'core':core,'accountId':'acct_alice','deviceId':'dev_1','pairingGeneration':1,'grantRevision':1,'conversationId':'conv_native','messageId':'msg_native','sessionId':'native_one'}
        token=device_tools.trusted_turn.set(origin)
        try:
            task=asyncio.create_task(device_tools.execute(core,args,session_id='native_one'))
            for _ in range(20):
                await asyncio.sleep(.02)
                a=core.open_gateway_account('acct_alice')
                try:
                    row=a.store.database.execute('SELECT request_id FROM device_requests').fetchone()
                    if row:
                        request=a.device_requests.get(row[0]);assert request['state']=='pending';assert request['requiresForegroundConfirmation']
                        claim=a.device_requests.claim(row[0],'dev_1',1,1,'cor_claim')
                        a.device_requests.submit_result(row[0],'dev_1',1,1,claim['claimId'],{'outcome':'succeeded','data':{'records':['actual-device-result']}},'cor_result')
                        request_id=row[0];claim_id=claim['claimId'];break
                finally:a.close()
            else:raise AssertionError('device request was not emitted')
            result=await asyncio.wait_for(task,3)
            assert result['data']=={'records':['actual-device-result']}
            a=core.open_gateway_account('acct_alice')
            try:assert a.device_requests.read_result(request_id,claim_id) is not None
            finally:a.close()
            device_tools.acknowledge_adopted(core,tool_name=device_tools.TOOL_NAME,session_id='native_one',status='ok',result={**result,'data':{'records':['altered']}})
            a=core.open_gateway_account('acct_alice')
            try:assert a.device_requests.read_result(request_id,claim_id) is not None
            finally:a.close()
            device_tools.acknowledge_adopted(core,tool_name=device_tools.TOOL_NAME,session_id='native_one',status='ok',result=json.dumps(result))
            a=core.open_gateway_account('acct_alice')
            try:
                assert a.device_requests.read_result(request_id,claim_id) is None
                assert all(not event['payload'].get('parameters') for event in a.events.read_after(None) if event['eventType']=='device.requested')
            finally:a.close()
        finally:device_tools.trusted_turn.reset(token)
    asyncio.run(scenario())
    a=core.open_gateway_account('acct_alice')
    try:
        a.device_requests.enqueue('ephemeral_disconnect','dev_1',1,1,binding['risk'],{'id':binding['capabilityId'],'version':'1.0.0'},{'pluginId':binding['pluginId'],'authorKeyId':binding['authorKeyId']},{'limit':1},'cor_disconnect',online=True)
        core.set_device_online(context,True);core.set_device_online(context,False)
        assert a.device_requests.get('ephemeral_disconnect')['state']=='pending'
        core.set_device_online(context,False)
        assert a.device_requests.get('ephemeral_disconnect')['state']=='expired'
        with pytest.raises(GatewayError,match='OUTCOME_UNKNOWN'):a.device_requests.claim('ephemeral_disconnect','dev_1',1,1,'cor_claim')
    finally:a.close()
    assert not core.is_device_online('acct_alice','dev_1',1)
