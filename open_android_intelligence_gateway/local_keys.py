"""Operator-provided master key file for the Gateway (ADR 0023).

The accepted design prefers a host Secret Store and, when the host has none,
lets the deployment operator supply a permission-restricted dedicated key file.
Hermes exposes no Secret Store to plugins, so this file is the supported
fallback: it is never written into ordinary configuration, logs, backups or
diagnostics, and it never lives next to the database it protects.

Every account gets its own derived key, so one deployment can host many
logically isolated Gateways without sharing key material (ADR 0030). A missing
file, a symlink, a foreign owner or group/other permission bits are refused
outright: an unusable key source must stop the Gateway from starting rather
than silently degrade into answers the phone cannot use.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Mapping

# Primary name follows the plugin's OPEN_ANDROID_INTELLIGENCE_* convention; the
# shorter alias keeps parity with OPEN_ANDROID_GATEWAY_HOST/PORT.
MASTER_KEY_FILE_ENV = "OPEN_ANDROID_INTELLIGENCE_GATEWAY_MASTER_KEY_FILE"
MASTER_KEY_FILE_ENV_ALIAS = "OPEN_ANDROID_GATEWAY_MASTER_KEY_FILE"

KEY_BYTES = 32
NONCE_BYTES = 12
ALGORITHM = "AES-256-GCM"
REFERENCE_PREFIX = "local-key-v1:"


class MasterKeyUnavailable(RuntimeError):
    """The configured key source is missing, unsafe, or unusable."""


DEFAULT_KEY_DIRECTORY_NAME = ".open-android-intelligence"
DEFAULT_KEY_FILE_NAME = "gateway-master-key"


def default_master_key_path() -> Path:
    """Deliberately outside the Hermes home: the key never travels with the database."""
    return Path.home() / DEFAULT_KEY_DIRECTORY_NAME / DEFAULT_KEY_FILE_NAME


def _write_new_key(target: Path) -> Path:
    directory = target.parent
    created_directory = not directory.exists()
    directory.mkdir(parents=True, exist_ok=True)
    if created_directory:
        # Tighten only the directory this call created: an operator-supplied
        # existing directory may hold unrelated files, and the key's own 0600
        # mode is what actually protects the material.
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
    handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(handle, os.urandom(KEY_BYTES))
        os.fsync(handle)
    finally:
        os.close(handle)
    os.chmod(target, 0o600)
    return target


def create_master_key_file(path: str | Path) -> Path:
    """Explicit one-shot provisioning used by ``hermes-account.py init-key``.

    Refuses to overwrite an existing file so a mistyped command cannot destroy a
    key that still protects live data.
    """
    return _write_new_key(Path(path).expanduser())


def ensure_master_key_file(path: str | Path) -> Path:
    """The automatic path an installer or first start takes.

    Installing the plugin is the operator's act of providing the key source, so
    the Gateway provisions it here instead of asking for a manual step. An
    existing file is never rewritten; unsafe files still fail closed later.
    """
    target = Path(path).expanduser()
    if target.exists() or target.is_symlink():
        return target
    return _write_new_key(target)


def master_key_file(environ: Mapping[str, str] | None = None) -> Path | None:
    source = environ if environ is not None else os.environ
    raw = source.get(MASTER_KEY_FILE_ENV) or source.get(MASTER_KEY_FILE_ENV_ALIAS)
    if not isinstance(raw, str) or not raw.strip():
        return None
    return Path(raw.strip()).expanduser()


def _read_key_bytes(path: Path) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise MasterKeyUnavailable(
            f"主密钥文件不存在：{path}。请执行 ./hermes-account.py init-key 生成后重启网关。"
        ) from exc
    if stat.S_ISLNK(info.st_mode):
        raise MasterKeyUnavailable(f"主密钥文件不能是符号链接：{path}")
    if not stat.S_ISREG(info.st_mode):
        raise MasterKeyUnavailable(f"主密钥文件必须是普通文件：{path}")
    if info.st_uid != os.getuid():
        raise MasterKeyUnavailable(f"主密钥文件必须属于当前用户：{path}")
    if info.st_mode & 0o077:
        raise MasterKeyUnavailable(
            f"主密钥文件权限过于宽松（{oct(info.st_mode & 0o777)}）：{path}，必须是 0600。"
        )
    raw = path.read_bytes()
    if len(raw) == KEY_BYTES:
        return raw
    text = raw.decode("utf-8", errors="strict").strip()
    if len(text) == KEY_BYTES * 2:
        try:
            decoded = bytes.fromhex(text)
        except ValueError as exc:
            raise MasterKeyUnavailable(f"主密钥文件既不是 32 字节原始密钥，也不是十六进制：{path}") from exc
        if len(decoded) == KEY_BYTES:
            return decoded
    raise MasterKeyUnavailable(
        f"主密钥内容长度不合法：{path}，需要 32 字节原始密钥或 64 位十六进制。"
    )


class LocalAeadProvider:
    """AES-256-GCM with the reference/algorithm shape the Core validates."""

    algorithm = ALGORITHM
    authenticated = True

    def __init__(self, reference: str, key: bytes) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self.reference = reference
        self.key_reference = reference
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        return nonce + self._aead.encrypt(nonce, bytes(plaintext), bytes(associated))

    def decrypt(self, ciphertext: bytes, associated: bytes) -> bytes:
        raw = bytes(ciphertext)
        if len(raw) <= NONCE_BYTES:
            raise ValueError("MASTER_KEY_CIPHERTEXT_TOO_SHORT")
        return self._aead.decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], bytes(associated))


class LocalMasterKeyStore:
    """Per-account derived keys from one operator-provided key file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    def validate(self) -> None:
        _read_key_bytes(self.path)

    def _derive(self, name: str) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        return HKDF(
            algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None,
            info=str(name).encode("utf-8"),
        ).derive(_read_key_bytes(self.path))

    def get_or_create_aead(self, name: str) -> LocalAeadProvider:
        # "get_or_create" is the host-facing name: this source never invents a
        # key, it derives a stable per-account key from the file that already
        # exists, so an unprovisioned deployment keeps failing closed.
        reference = REFERENCE_PREFIX + hashlib.sha256(str(name).encode("utf-8")).hexdigest()[:16]
        return LocalAeadProvider(reference, self._derive(name))


def resolve_local_master_key_store(environ: Mapping[str, str] | None = None) -> LocalMasterKeyStore:
    """The key source used when the host exposes no Secret Store.

    Provisioning is automatic so a freshly installed plugin is usable after
    ``hermes gateway setup`` alone; it still refuses to start on a file the
    operator placed with unsafe ownership or permissions.
    """
    path = master_key_file(environ) or default_master_key_path()
    try:
        ensured = ensure_master_key_file(path)
    except OSError as exc:
        raise MasterKeyUnavailable(
            f"无法自动创建主密钥文件 {path}: {exc}。请把 "
            f"{MASTER_KEY_FILE_ENV} 指向一个可写的专用路径，或执行 "
            "./hermes-account.py init-key 手动生成。"
        ) from exc
    return LocalMasterKeyStore(ensured)


def master_key_unavailable_reason(core: Any) -> str | None:
    """Why the Gateway must refuse to start, or None when a key source is usable."""
    store = getattr(core, "secret_store", None)
    if store is None:
        return (
            "主密钥来源不可用：宿主未提供 Secret Store，且受限密钥文件无法自动创建。"
            f"请检查 {default_master_key_path()} 所在目录是否可写，或通过 "
            f"{MASTER_KEY_FILE_ENV} 指定一个可写的专用路径。缺少主密钥时网关拒绝启动，"
            "避免所有已认证请求以 400 失败。"
        )
    validate = getattr(store, "validate", None)
    if callable(validate):
        try:
            validate()
        except Exception as exc:  # noqa: BLE001 - the reason is the operator-facing message
            return f"主密钥来源不可用：{exc}"
    return None
