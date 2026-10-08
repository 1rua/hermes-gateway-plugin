"""History assets refer to host-owned originals, never the Gateway staging directory."""
from __future__ import annotations
import hashlib,mimetypes,os,secrets
from pathlib import Path
from datetime import timedelta
from .core import GatewayError,_jcs,_now,iso_millis

MAX_MEDIA_BYTES=25*1024*1024
class HistoryMedia:
    def __init__(self,account): self.account=account; self.store=account.store
    def _get(self,key):
        row=self.store.database.execute('SELECT value FROM account_metadata WHERE key=?',(key,)).fetchone()
        return self.store.open_json(row[0],key) if row else None
    def _put(self,key,value): self.store.database.execute('INSERT OR REPLACE INTO account_metadata(key,value) VALUES (?,?)',(key,self.store.seal_json(value,key)))
    def reply_parts(self, message_id):
        prefix = f"history-media-reply:{message_id}:"
        rows = self.store.database.execute(
            "SELECT key,value FROM account_metadata WHERE substr(key,1,?)=? ORDER BY rowid",
            (len(prefix), prefix)).fetchall()
        return [self.store.open_json(row[1], row[0]) for row in rows]
    def register(self,conversation_id,message_id,path,media_type=None):
        try:
            from gateway.platforms.base import validate_media_delivery_path
            safe_path = validate_media_delivery_path(str(path))
            if safe_path is None: raise GatewayError('ATTACHMENT_NOT_FOUND')
            path = safe_path
        except ImportError:
            home=Path(os.environ.get('HERMES_HOME',str(Path.home()/'.hermes'))).resolve()
            file=Path(path).resolve()
            if not any(file.is_relative_to(home/folder) for folder in ('cache','outputs')): raise GatewayError('ATTACHMENT_NOT_FOUND')
        file=Path(path).resolve(strict=True)
        if not file.is_file() or file.stat().st_size>MAX_MEDIA_BYTES: raise GatewayError('ATTACHMENT_TOO_LARGE')
        with file.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
        media_id='media_'+hashlib.sha256(_jcs([self.account.account_id,conversation_id,message_id,str(file),digest]).encode()).hexdigest()[:48]
        record={'attachmentId':media_id,'conversationId':conversation_id,'messageId':message_id,'filename':file.name,'mediaType':media_type or mimetypes.guess_type(file.name)[0] or 'application/octet-stream','sizeBytes':file.stat().st_size,'sha256':'sha256:'+digest,'path':str(file)}
        self._put('history-media:'+media_id,record)
        return {k:v for k,v in record.items() if k not in {'path','conversationId','messageId'}}|{'type':'attachment'}
    def _record(self,conversation_id,media_id):
        row=self._get('history-media:'+media_id)
        if not row or row['conversationId']!=conversation_id: raise GatewayError('ATTACHMENT_NOT_FOUND')
        self.account.conversations.get(conversation_id)
        return row
    def metadata(self,conversation_id,media_id):
        row=self._record(conversation_id,media_id)
        try:
            file=Path(row['path'])
            available=file.is_file() and file.stat().st_size==row['sizeBytes']
            if available:
                with file.open('rb') as stream: available='sha256:'+hashlib.file_digest(stream,'sha256').hexdigest()==row['sha256']
        except OSError: available=False
        return {k:v for k,v in row.items() if k!='path'}|{'remoteAvailable':available,'status':'AVAILABLE' if available else 'REMOTE_UNAVAILABLE','estimatedLocalBytes':row['sizeBytes']+512}
    def grant(self,conversation_id,media_id,context,now=None):
        metadata=self.metadata(conversation_id,media_id)
        if not metadata['remoteAvailable']: raise GatewayError('ATTACHMENT_NOT_FOUND')
        token=secrets.token_urlsafe(32); expires=iso_millis(_now(now)+timedelta(seconds=120))
        self._put('history-media-grant:'+hashlib.sha256(token.encode()).hexdigest(),{'attachmentId':media_id,'conversationId':conversation_id,'deviceId':context['deviceId'],'pairingGeneration':context['pairingGeneration'],'grantRevision':context['grantRevision'],'expiresAt':expires})
        return {'grantId':token,'expiresAt':expires,'metadata':metadata}
    def content(self,conversation_id,media_id,token,context,now=None):
        key='history-media-grant:'+hashlib.sha256(token.encode()).hexdigest()
        with self.store.transaction():
            saved=self._get(key)
            if not saved or _now(saved['expiresAt'])<=_now(now) or any(saved[k]!=v for k,v in {'attachmentId':media_id,'conversationId':conversation_id,'deviceId':context['deviceId'],'pairingGeneration':context['pairingGeneration'],'grantRevision':context['grantRevision']}.items()): raise GatewayError('AUTHENTICATION_FAILED')
            self.store.database.execute('DELETE FROM account_metadata WHERE key=?',(key,))
            row=self._record(conversation_id,media_id)
            try:
                fd=os.open(row['path'],os.O_RDONLY|os.O_NOFOLLOW)
                with os.fdopen(fd,'rb') as stream: data=stream.read(MAX_MEDIA_BYTES+1)
            except OSError as exc: raise GatewayError('ATTACHMENT_NOT_FOUND') from exc
            if len(data)!=row['sizeBytes'] or 'sha256:'+hashlib.sha256(data).hexdigest()!=row['sha256']: raise GatewayError('ATTACHMENT_NOT_FOUND')
            return data,row['mediaType']
