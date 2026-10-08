"""One-use, account-fenced invitations; possession of a code never replaces device-key proof."""
from __future__ import annotations
import base64
import hashlib
import secrets
import uuid
from datetime import timedelta
from urllib.parse import urlparse,urlencode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .core import GatewayError,_jcs,_now,iso_millis,canonical_device_key,CredentialStore

class PairingInvites:
    def __init__(self,account): self.account=account; self.store=account.store
    def _put(self,key,value):
        self.store.database.execute("INSERT OR REPLACE INTO account_metadata(key,value) VALUES (?,?)",(key,self.store.seal_json(value,key)))
    def _get(self,key):
        row=self.store.database.execute("SELECT value FROM account_metadata WHERE key=?",(key,)).fetchone()
        return self.store.open_json(row[0],key) if row else None
    def _credential(self): return CredentialStore(self.store).password_digest()
    def _prune(self, current):
        rows = self.store.database.execute("SELECT key,value FROM account_metadata WHERE key LIKE 'pairing-invite:%' OR key LIKE 'pairing-challenge:%'").fetchall()
        for row in rows:
            saved = self.store.open_json(row[1], row[0])
            expires = saved.get('expiresAt') or saved.get('facts', {}).get('expiresAt')
            if not expires or _now(expires) <= current:
                self.store.database.execute("DELETE FROM account_metadata WHERE key=?", (row[0],))
        count = self.store.database.execute("SELECT COUNT(*) FROM account_metadata WHERE key LIKE 'pairing-invite:%' OR key LIKE 'pairing-challenge:%'").fetchone()[0]
        if count >= 128: raise GatewayError('RATE_LIMITED')

    def issue(self,gateway_url,ttl_seconds=300,now=None,gateway_identity=None):
        current=_now(now); url=urlparse(gateway_url)
        if url.scheme not in ('http','https') or not url.hostname or url.username or url.password or url.query or url.fragment or not 30<=ttl_seconds<=900: raise GatewayError('SCHEMA_INVALID')
        self._prune(current)
        invitation_id='invite_'+str(uuid.uuid4())
        code=secrets.token_hex(8).upper(); expires_at=iso_millis(current+timedelta(seconds=ttl_seconds))
        self._put('pairing-invite:'+hashlib.sha256(code.encode()).hexdigest(),{'invitationId':invitation_id,'expiresAt':expires_at,'credential':self._credential(),'pairingGeneration':self.account.pairing_generation()})
        fingerprint='sha256:'+hashlib.sha256(_jcs(gateway_identity or {}).encode()).hexdigest()
        return {'invitationId':invitation_id,'code':code,'expiresAt':expires_at,'gatewayIdentityFingerprint':fingerprint,'qrPayload':'oai://pair?'+urlencode({'gateway':gateway_url.rstrip('/'),'account':self.account.account_id,'invitationId':invitation_id,'code':code,'expiresAt':expires_at,'identityFingerprint':fingerprint})}
    def challenge(self,code,negotiation_id,installation,now=None):
        current=_now(now)
        self._prune(current)
        if not isinstance(code,str) or len(code)!=16 or any(c not in '0123456789ABCDEF' for c in code) or not canonical_device_key(installation.get('devicePublicKey')) or not installation.get('installationId') or not isinstance(installation.get('displayName'),str) or not 1<=len(installation['displayName'])<=200: raise GatewayError('AUTHENTICATION_FAILED')
        invite_key='pairing-invite:'+hashlib.sha256(code.encode()).hexdigest(); invitation=self._get(invite_key)
        if not invitation or _now(invitation['expiresAt'])<=current or invitation['credential']!=self._credential() or invitation['pairingGeneration']!=self.account.pairing_generation(): raise GatewayError('AUTHENTICATION_FAILED')
        facts={'challengeId':'challenge_'+str(uuid.uuid4()),'accountId':self.account.account_id,'negotiationId':negotiation_id,'installationId':installation['installationId'],'devicePublicKey':installation['devicePublicKey'],'nonce':secrets.token_urlsafe(32),'expiresAt':iso_millis(min(current+timedelta(seconds=60),_now(invitation['expiresAt'])))}
        self._put('pairing-challenge:'+facts['challengeId'],{'facts':facts,'installation':dict(installation),'inviteKey':invite_key})
        return facts
    def exchange(self,challenge_id,signature,negotiation_id,correlation_id,now=None):
        if not isinstance(challenge_id,str) or not isinstance(signature,str) or len(signature)!=86 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in signature): raise GatewayError('AUTHENTICATION_FAILED')
        current=_now(now); key='pairing-challenge:'+challenge_id
        with self.store.transaction():
            saved=self._get(key); facts=saved.get('facts') if saved else None; invitation=self._get(saved['inviteKey']) if saved else None
            if not saved or not facts or not invitation or facts['negotiationId']!=negotiation_id or _now(facts['expiresAt'])<=current or invitation['credential']!=self._credential() or invitation['pairingGeneration']!=self.account.pairing_generation(): raise GatewayError('AUTHENTICATION_FAILED')
            try:
                decoded=base64.b64decode(signature+'==',altchars=b'-_',validate=True)
                if base64.urlsafe_b64encode(decoded).rstrip(b'=').decode()!=signature: raise ValueError('noncanonical signature')
                Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(facts['devicePublicKey']+'=')).verify(decoded,b'OPEN_ANDROID_INTELLIGENCE_PAIRING_V1\n'+_jcs(facts).encode())
            except Exception as exc: raise GatewayError('AUTHENTICATION_FAILED') from exc
            self.store.database.execute('DELETE FROM account_metadata WHERE key IN (?,?)',(key,saved['inviteKey']))
            installation=saved['installation']; sessions=self.account.sessions
            bundle=sessions._issue(installation['installationId'],'dev_'+str(uuid.uuid4()),current)
            sessions._register_device_key(bundle['deviceId'],installation['installationId'],installation['devicePublicKey'],current)
            self.account.audit.append('session.invite.created',{'accountId':self.account.account_id,'deviceId':bundle['deviceId']},{'method':'account-invitation'},correlation_id,current)
            bundle.update({'pairingGeneration':self.account.pairing_generation(),'grantRevision':1})
            return bundle

    def device_challenge(self,negotiation_id,installation_id,device_id,now=None):
        current=_now(now); self._prune(current)
        row=self.store.database.execute('SELECT public_key,pairing_generation,grant_revision FROM device_keys WHERE device_id=? AND installation_id=?',(device_id,installation_id)).fetchone()
        if not row: raise GatewayError('AUTHENTICATION_FAILED')
        facts={'challenge':'challenge_'+str(uuid.uuid4()),'accountId':self.account.account_id,'negotiationId':negotiation_id,'installationId':installation_id,'deviceId':device_id,
               'nonce':secrets.token_urlsafe(32),'expiresAt':iso_millis(current+timedelta(seconds=60))}
        self._put('pairing-challenge:'+facts['challenge'],{'facts':facts,'publicKey':row[0],'pairingGeneration':row[1],'credential':self._credential()})
        return facts

    def device_exchange(self,body,correlation_id,now=None):
        current=_now(now); key='pairing-challenge:'+body['challenge']
        with self.store.transaction():
            saved=self._get(key); facts=saved.get('facts',{}) if saved else {}
            row=self.store.database.execute('SELECT public_key,pairing_generation FROM device_keys WHERE device_id=? AND installation_id=?',(body['deviceId'],body['installationId'])).fetchone()
            if not saved or not row or saved.get('publicKey')!=row[0] or saved.get('pairingGeneration')!=row[1] or saved.get('credential')!=self._credential() or _now(facts['expiresAt'])<=current or any(facts[k]!=body[k] for k in ('challenge','negotiationId','installationId','deviceId')): raise GatewayError('AUTHENTICATION_FAILED')
            try:
                signature=body['signature']; decoded=base64.b64decode(signature+'==',altchars=b'-_',validate=True)
                if base64.urlsafe_b64encode(decoded).rstrip(b'=').decode()!=signature: raise ValueError('noncanonical signature')
                Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(row[0]+'=')).verify(decoded,b'OPEN_ANDROID_INTELLIGENCE_DEVICE_SESSION_V1\n'+_jcs(facts).encode())
            except Exception as exc: raise GatewayError('AUTHENTICATION_FAILED') from exc
            self.store.database.execute('DELETE FROM account_metadata WHERE key=?',(key,))
            bundle=self.account.sessions._issue(body['installationId'],body['deviceId'],current)
            self.account.audit.append('session.device.created',{'accountId':self.account.account_id,'deviceId':body['deviceId']},{'method':'device-key'},correlation_id,current)
            return bundle
