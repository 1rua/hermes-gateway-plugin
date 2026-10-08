"""Exercise persisted batch identities and native cancellation boundaries."""
import sys
from pathlib import Path
from datetime import datetime, timezone
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway.core import GatewayError, create_gateway_core
from test_support import make_secret_store

def setup(tmp_path):
    core=create_gateway_core(tmp_path,secret_store=make_secret_store())
    account=core.open_gateway_account('acct_workflow')
    cid=account.conversations.create('cc_workflow',None,'cor_create')['conversationId']
    context={'accountId':account.account_id,'deviceId':'dev_workflow','pairingGeneration':1,'grantRevision':1,'requestId':'req_batch','correlationId':'cor_batch'}
    body={'clientBatchId':'cb_one','joinMode':'newline-v1','members':[{'clientMessageId':'cm_one','text':'  中文\n'},{'clientMessageId':'cm_two','text':'🙂 second  '}]}
    return account,cid,context,body

def test_frozen_batch_replay_exact_join_and_single_generation(tmp_path):
    a,cid,ctx,body=setup(tmp_path)
    try:
        workflow=a.conversations.workflow
        with a.store.transaction(): receipt=workflow.accept_batch(cid,body,ctx,datetime.now(timezone.utc))
        with a.store.transaction(): assert workflow.accept_batch(cid,body,{**ctx,'requestId':'req_retry'},datetime.now(timezone.utc))==receipt
        events=a.events.read_after(None)
        assert len(events)==2 and {e['payload']['generationId'] for e in events}=={receipt['generationId']}
        dispatch=a.conversations.claim_dispatch('cm_one')
        assert dispatch['text']=='  中文\n\n🙂 second  '
        assert a.conversations.claim_dispatch('cm_two') is None
        assert a.conversations.claim_dispatch('cm_one') is None
        changed={**body,'members':[{'clientMessageId':'cm_one','text':'changed'}]}
        with pytest.raises(GatewayError,match='IDEMPOTENCY_CONFLICT'):
            with a.store.transaction(): workflow.accept_batch(cid,changed,ctx,datetime.now(timezone.utc))
        with pytest.raises(GatewayError,match='IDEMPOTENCY_CONFLICT'):
            with a.store.transaction(): workflow.accept_batch(cid,body,{**ctx,'deviceId':'dev_other'},datetime.now(timezone.utc))
        row={'messageId':dispatch['messageId'],'sender':'user','text':dispatch['text'],'state':'CONFIRMED','parts':[]}
        expanded=workflow.expand_history(row)
        assert [m['text'] for m in expanded]==[m['text'] for m in body['members']]
        assert [m['messageId'] for m in expanded]==[m['messageId'] for m in receipt['members']]
    finally: a.close()

def test_unknown_cancellation_pauses_fifo_until_native_receipt(tmp_path):
    a,cid,ctx,body=setup(tmp_path)
    try:
        w=a.conversations.workflow
        with a.store.transaction(): receipt=w.accept_batch(cid,body,ctx,datetime.now(timezone.utc))
        first=a.conversations.claim_dispatch('cm_one')
        second=a.conversations.accept_message(cid,'cm_later','later',[],ctx['deviceId'],'req_later','cor_later')
        assert a.conversations.claim_dispatch('cm_later') is None
        assert w.prepare_cancel(cid,receipt['generationId'],ctx,lambda *_:'OUTCOME_UNKNOWN')=='OUTCOME_UNKNOWN'
        assert a.conversations.claim_dispatch('cm_later') is None
        with pytest.raises(GatewayError,match='PAIRING_GENERATION_STALE'):
            w.prepare_cancel(cid,receipt['generationId'],{**ctx,'deviceId':'dev_other'},lambda *_:'CANCELLED')
        with a.store.transaction(): w.finish_cancel(cid,receipt['generationId'],'CANCELLED',ctx,datetime.now(timezone.utc))
        assert w.for_message(first['messageId'])['state']=='cancelled'
        assert all(not r[0] for r in a.store.database.execute('SELECT text FROM messages WHERE message_id IN (?,?)',tuple(m['messageId'] for m in receipt['members'])))
        assert a.conversations.claim_dispatch('cm_later')['messageId']==second['messageId']
    finally:a.close()

@pytest.mark.parametrize('member',[{'clientMessageId':'cm_bad','text':' /new'},{'clientMessageId':'cm_bad','text':'x','attachmentId':'att_bad'},{'clientMessageId':'cm_bad','text':'x'*65537}])
def test_batch_rejects_commands_attachments_and_oversized_text(tmp_path,member):
    a,cid,ctx,body=setup(tmp_path)
    try:
        with pytest.raises(GatewayError,match='SCHEMA_INVALID'):
            with a.store.transaction(): a.conversations.workflow.accept_batch(cid,{**body,'members':[member]},ctx,datetime.now(timezone.utc))
        assert a.store.database.execute('SELECT COUNT(*) FROM messages').fetchone()[0]==0
    finally:a.close()
