"""Real Ed25519 proof, invitation expiry/reuse and device session account fences."""
import base64
import hashlib
import sys
from pathlib import Path
from datetime import datetime,timedelta,timezone
from urllib.parse import urlparse,parse_qs
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from open_android_intelligence_gateway.core import GatewayError,create_gateway_core,_jcs
from open_android_intelligence_gateway.adapter import AccountPasswordVerifier
from open_android_intelligence_gateway.pairing_invites import PairingInvites
from test_support import make_secret_store,core_schema_hash

def b64(value):return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
def setup(tmp_path):
    core=create_gateway_core(tmp_path,secret_store=make_secret_store())
    core.credential_verifier=AccountPasswordVerifier(core)
    a=core.open_gateway_account('acct_invite');a.credentials.create_password('actual-test-password')
    private=Ed25519PrivateKey.generate()
    installation={'installationId':'install_one','displayName':'phone','devicePublicKey':b64(private.public_key().public_bytes_raw())}
    return core,a,private,installation

def test_default_expiry_real_proof_one_use_and_no_secret_in_audit(tmp_path):
    core,a,private,installation=setup(tmp_path);now=datetime.now(timezone.utc)
    try:
        service=PairingInvites(a);identity={'deploymentId':'deploy_test','tlsSpkiSha256':None}
        invite=service.issue('https://gateway.example',now=now,gateway_identity=identity)
        assert datetime.fromisoformat(invite['expiresAt'].replace('Z','+00:00'))-now < timedelta(seconds=301)
        query=parse_qs(urlparse(invite['qrPayload']).query)
        assert query['invitationId']==[invite['invitationId']]
        assert query['identityFingerprint']==['sha256:'+hashlib.sha256(_jcs(identity).encode()).hexdigest()]
        facts=service.challenge(invite['code'],'neg_one',installation,now)
        signature=b64(private.sign(b'OPEN_ANDROID_INTELLIGENCE_PAIRING_V1\n'+_jcs(facts).encode()))
        with pytest.raises(GatewayError):service.exchange(facts['challengeId'],signature,'neg_wrong','cor_bad',now)
        session=service.exchange(facts['challengeId'],signature,'neg_one','cor_one',now)
        with pytest.raises(GatewayError):service.exchange(facts['challengeId'],signature,'neg_one','cor_replay',now)
        assert session['deviceId'].startswith('dev_')
        audit=str(a.audit.list());assert 'account-invitation' in audit and invite['code'] not in audit
        expired=service.issue('https://gateway.example',now=now)
        with pytest.raises(GatewayError):service.challenge(expired['code'],'neg_expired',installation,now+timedelta(minutes=6))
    finally:a.close()

def test_device_key_endpoint_requires_scoped_negotiation_and_consumes_challenge(tmp_path):
    core,a,private,installation=setup(tmp_path)
    try:
        session=a.sessions.create_password_session(a.account_id,'actual-test-password',installation,'cor_password')
    finally:a.close()
    negotiate={'negotiationId':'neg_device','protocol':{'major':2,'minor':1},'client':{'installationId':'install_one','appVersion':'2.1.0','platform':'android','platformApi':35},
        'features':{'auth':['password','account-invitation','refresh','device-key'],'messages':['chat-v1'],'attachments':['staged-sha256-v1'],'events':['sse-cursor-v1'],'deviceRequests':['risk-queue-v1']},'schemaHashes':{'core':core_schema_hash()}}
    assert 'error' not in core.handle({'method':'POST','target':'/open-android-intelligence/v2/negotiate','body':negotiate})
    binding={'negotiationId':'neg_device','accountId':'acct_invite','installationId':'install_one','deviceId':session['deviceId']}
    response=core.handle({'method':'POST','target':'/open-android-intelligence/v2/sessions/device/challenge','body':binding})
    assert 'error' not in response
    facts=response['data'];request={**binding,'challenge':facts['challenge'],'signature':b64(private.sign(b'OPEN_ANDROID_INTELLIGENCE_DEVICE_SESSION_V1\n'+_jcs(facts).encode()))}
    wrong=core.handle({'method':'POST','target':'/open-android-intelligence/v2/sessions/device','body':{**request,'accountId':'acct_other'}})
    assert wrong['error']['code']=='AUTHENTICATION_FAILED'
    response=core.handle({'method':'POST','target':'/open-android-intelligence/v2/sessions/device','body':request})
    assert response['data']['deviceId']==session['deviceId'] and response['data']['sessionId']!=session['sessionId']
    replay=core.handle({'method':'POST','target':'/open-android-intelligence/v2/sessions/device','body':request})
    assert replay['error']['code']=='AUTHENTICATION_FAILED'
