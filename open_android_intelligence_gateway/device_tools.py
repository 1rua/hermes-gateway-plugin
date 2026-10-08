"""Native Hermes tools: all routing facts come from the running host session."""
from __future__ import annotations
import asyncio
from contextvars import ContextVar
import hashlib
import json
import threading
import uuid
from typing import Any, Mapping

TOOL_NAME = "open_android_device"
trusted_turn: ContextVar[dict[str, Any] | None] = ContextVar("oai_trusted_device_turn",default=None)
_pending: dict[tuple[int,str,str], tuple[str,str,str]] = {}
_pending_lock = threading.RLock()

TOOL_SCHEMA = {"name":TOOL_NAME,"description":"Invoke a capability explicitly granted on the paired Android device. The host selects the device and provider.",
    "parameters":{"type":"object","additionalProperties":False,"required":["capabilityId","capabilityVersion","parameters"],
        "properties":{"capabilityId":{"type":"string","maxLength":256},"capabilityVersion":{"type":"string","pattern":r"^\d+\.\d+\.\d+$"},"parameters":{"type":"object"}}}}

def resolve_origin(core: Any,session_id: str,account_hint: str | None = None,conversation_hint: str | None = None) -> dict[str, Any] | None:
    turn = trusted_turn.get()
    if turn is not None and turn.get("core") is core and (not session_id or turn.get("sessionId") == session_id):
        return turn
    history = getattr(core.history_reader,"__self__",None)
    db = getattr(getattr(history,"session_store",None),"_db",None)
    if db is None: return None
    for account_id in ([account_hint] if account_hint else core.list_gateway_account_ids()):
        account = core.open_gateway_account(account_id)
        try:
            if conversation_hint:
                binding = account.agent_sessions.lookup(conversation_hint)
                if not binding or not binding.get("agentSessionId"): continue
                candidates = [(conversation_hint,binding["agentSessionId"])]
            else:
                candidates = [(row[0],row[1]) for row in account.store.database.execute(
                    "SELECT conversation_id,agent_session_id FROM conversation_agent_sessions WHERE agent_session_id=?",(session_id,)).fetchall()]
            for conversation_id,native_id in candidates:
                if session_id and native_id != session_id: continue
                messages = db.get_messages(native_id)
                user = next((row for row in reversed(messages) if row.get("role") == "user"),None)
                platform_id = user.get("platform_message_id") if user else None
                if not platform_id: continue
                origin = account.store.database.execute("SELECT value FROM account_metadata WHERE key=?",(f"message-device:{platform_id}",)).fetchone()
                if origin:
                    result = json.loads(origin[0])
                    if result["conversationId"] != conversation_id: continue
                    return {**result,"accountId":account_id,"sessionId":native_id,"core":core}
        finally: account.close()
    return None

async def execute(core: Any,args: Mapping[str, Any],**host_context: Any) -> dict[str, Any]:
    from .core import GatewayError, _jcs, _now
    if not isinstance(args,Mapping) or set(args) != {"capabilityId","capabilityVersion","parameters"} or not isinstance(args["parameters"],dict):
        raise GatewayError("SCHEMA_INVALID")
    origin = resolve_origin(core,str(host_context.get("session_id") or ""))
    if origin is None: raise GatewayError("PAIRING_REQUIRED")
    account_id,device_id = origin["accountId"],origin["deviceId"]
    account = core.open_gateway_account(account_id)
    request_id = f"devreq_{uuid.uuid4()}"
    try:
        device = account.store.database.execute("SELECT pairing_generation,grant_revision FROM device_keys WHERE device_id=?",(device_id,)).fetchone()
        if not device or int(device[0]) != origin["pairingGeneration"] or int(device[1]) != origin["grantRevision"]:
            raise GatewayError("GRANT_STALE")
        bindings = account.device_requests.capabilities.list(device_id,int(device[0]),int(device[1]))
        binding = next((item for item in bindings if item["capabilityId"] == args["capabilityId"] and item["capabilityVersion"] == args["capabilityVersion"]),None)
        if binding is None: raise GatewayError("CAPABILITY_DENIED")
        queued = account.device_requests.enqueue(request_id,device_id,int(device[0]),int(device[1]),binding["risk"],
            {"id":binding["capabilityId"],"version":binding["capabilityVersion"]},{"pluginId":binding["pluginId"],"authorKeyId":binding["authorKeyId"]},
            args["parameters"],origin["messageId"],requires_foreground_confirmation=binding["risk"] in {"write","high-privilege-ephemeral"},
            online=core.is_device_online(account_id,device_id,int(device[0])))
        expires = _now(queued["expiresAt"]).timestamp()
    finally: account.close()
    try:
        while True:
            account = core.open_gateway_account(account_id)
            try:
                record = account.device_requests.get(request_id)
                receipt = account.store.database.execute("SELECT claim_id FROM claim_receipts WHERE request_id=?",(request_id,)).fetchone()
                if receipt and record["state"] in {"succeeded","failed","denied","cancelled","outcome_unknown"}:
                    result = account.device_requests.read_result(request_id,receipt[0])
                    response = {"requestId":request_id,**(result or {"outcome":"outcome_unknown"})}
                    if result is not None:
                        fingerprint = hashlib.sha256(_jcs(response).encode()).hexdigest()
                        with _pending_lock: _pending[(id(core),str(origin.get("sessionId") or ""),request_id)] = (account_id,receipt[0],fingerprint)
                    return response
                if record["state"] in {"expired","cancelled","outcome_unknown"} or _now().timestamp() >= expires:
                    account.device_requests.recover_expired()
                    return {"requestId":request_id,"outcome":"outcome_unknown","code":"DEVICE_OFFLINE" if record["state"] == "expired" else "DEVICE_TIMEOUT"}
            finally: account.close()
            await asyncio.sleep(0.2)
    except asyncio.CancelledError:
        # Host stop/cancellation must also fence the phone's queued invocation.
        # A claimed request remains cancel_requested: cancellation is not proof
        # that an already-started side effect did not happen.
        account = core.open_gateway_account(account_id)
        try:
            if account.device_requests.get(request_id)["state"] in {"pending", "claimed"}:
                account.device_requests.cancel(request_id,device_id,origin["pairingGeneration"],origin["grantRevision"],origin["messageId"])
        except GatewayError:
            # Expiry/revocation may have fenced the request while the host stopped.
            pass
        finally: account.close()
        raise

def acknowledge_adopted(core: Any,**event: Any) -> None:
    from .core import _jcs
    if event.get("tool_name") != TOOL_NAME or event.get("status") not in {None,"ok","success"}: return
    result = event.get("result")
    if isinstance(result,str):
        try: result = json.loads(result)
        except (TypeError,ValueError): return
    if not isinstance(result,dict) or not isinstance(result.get("requestId"),str): return
    key = (id(core),str(event.get("session_id") or ""),result["requestId"])
    with _pending_lock: pending = _pending.get(key)
    if pending is None or hashlib.sha256(_jcs(result).encode()).hexdigest() != pending[2]: return
    account = core.open_gateway_account(pending[0])
    try: account.device_requests.acknowledge_result(result["requestId"],pending[1])
    finally: account.close()
    with _pending_lock: _pending.pop(key,None)

def register_device_tools(ctx: Any,core: Any) -> None:
    register = getattr(ctx,"register_tool",None)
    hook = getattr(ctx,"register_hook",None) or getattr(ctx,"on",None)
    if not callable(register) or not callable(hook): return
    async def handler(args: dict[str,Any],**kwargs: Any) -> str:
        from .core import _jcs
        return _jcs(await execute(core,args,**kwargs))
    register(name=TOOL_NAME,toolset="open_android",schema=TOOL_SCHEMA,handler=handler,is_async=True,description=TOOL_SCHEMA["description"],emoji="📱")
    hook("post_tool_call",lambda **event: acknowledge_adopted(core,**event))
