"""Acquisition of the Gateway Protocol contract assets for the Hermes plugin.

The plugin repository ships no copy of the contract: the single source of
truth is the application repository's ``gateway-contract`` tree, and the
Schema digest negotiated with the phone is computed from exactly those files.
This module fetches that tree into the plugin directory at a pinned revision
so the core's existing upward lookup finds it, which keeps one authoritative
copy of the contract instead of two hand-maintained ones.

An unreachable or misconfigured source is reported, never hidden: the caller
receives ``source="unavailable"`` with an operator-facing reason so the Gateway
can present "contract not ready" instead of a false ready state.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterator, Mapping, NamedTuple

try:  # pragma: no cover - POSIX hosts, which is what Hermes runs on
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]

CONTRACT_DIRECTORY_NAME = "gateway-contract"
PIN_FILE_NAME = "contract-pin.json"
REVISION_MARKER_NAME = ".pinned-revision"
LOCK_FILE_NAME = ".contract.lock"

# An operator who already holds the contract — an offline bundle, an internal
# mirror, or a checkout inside the application repository — can point the
# plugin straight at it and skip the fetch entirely.
CONTRACT_ROOT_ENV = "OPEN_ANDROID_GATEWAY_CONTRACT_ROOT"
# Overrides the pin's repository only, for mirrors; the revision stays pinned.
CONTRACT_REPOSITORY_ENV = "OPEN_ANDROID_GATEWAY_CONTRACT_REPOSITORY"

# Mirrors the core's own readiness probe: both the schema and the vector set
# must be present, because the negotiated digest covers both.
DEFAULT_PROBES: tuple[str, ...] = (
    "schemas/envelope.schema.json",
    "vectors/vector-set-1.0.0.schema.json",
)

_FULL_COMMIT_SHA = re.compile(r"\A[0-9a-f]{40}\Z")


class ContractResolution(NamedTuple):
    """Where the contract was resolved from, and why not when it was not."""

    root: Path | None
    pinned_ref: str | None
    source: str
    reason: str | None


class PinError(RuntimeError):
    """The pin is missing, unreadable, or does not name an immutable revision."""


def _run_git(directory: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=directory, check=True, capture_output=True, text=True,
    )


def _read_pin(plugin_root: Path) -> dict[str, Any]:
    """Load and validate the pin.

    Validation is deliberately strict: a pin that names a branch or an
    abbreviated SHA would let the contract drift under an operator who believes
    it is pinned, and a missing pin means the plugin install is incomplete.
    Both are refused rather than guessed at.
    """
    path = plugin_root / PIN_FILE_NAME
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PinError(
            f"未找到契约锁定文件 {path}；插件无法确认协议契约版本。"
            f"请确认插件安装完整，或用环境变量 {CONTRACT_ROOT_ENV} 指定已就位的契约根目录。"
        ) from exc
    except (OSError, ValueError) as exc:
        raise PinError(f"契约锁定文件 {path} 无法解析：{exc}") from exc
    if not isinstance(document, dict):
        raise PinError(f"契约锁定文件 {path} 必须是一个 JSON 对象")

    repository = str(document.get("repository") or "").strip()
    revision = str(document.get("revision") or "").strip()
    if not repository:
        raise PinError(f"契约锁定文件 {path} 缺少 repository")
    if not _FULL_COMMIT_SHA.match(revision):
        raise PinError(
            f"契约锁定文件 {path} 的 revision 必须是 40 位完整提交 SHA，"
            f"当前为 {revision or '(空)'}；分支名或短 SHA 无法锁定契约版本。"
        )
    # A mirror may serve the same pinned revision from elsewhere; the revision
    # itself stays whatever the pin declared.
    mirror = os.environ.get(CONTRACT_REPOSITORY_ENV, "").strip()
    return {
        "repository": mirror or repository,
        "revision": revision,
        "probes": tuple(document.get("probes") or DEFAULT_PROBES),
    }


def _probe_paths(root: Path, probes: tuple[str, ...]) -> tuple[Path, ...]:
    return tuple(root / probe for probe in probes)


def _checkout(repository: str, revision: str, target: Path) -> None:
    """Materialise *revision*'s ``gateway-contract`` tree at *target*.

    A shallow ``clone`` cannot pin an arbitrary revision — it only ever
    fetches a branch tip — so the fetch is issued for the exact commit and
    checked out detached. The checkout happens in a sibling staging directory
    because the repository root holds ``gateway-contract/`` as a subtree: the
    core's upward lookup searches for ``<plugin_dir>/gateway-contract``, so the
    subtree has to land there directly rather than one level deeper.
    """
    staging = target.parent / f".{target.name}-staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        staging.mkdir(parents=True)
        _run_git(staging, "init")
        # The pinned repository is the whole application, so the checkout is
        # narrowed to the one directory the Gateway reads. Without this every
        # fresh install would write the entire Android tree to disk only to
        # keep a single subdirectory of it.
        _run_git(staging, "sparse-checkout", "init", "--cone")
        _run_git(staging, "sparse-checkout", "set", CONTRACT_DIRECTORY_NAME)
        _run_git(staging, "fetch", "--depth", "1", repository, revision)
        _run_git(staging, "checkout", "--detach", "FETCH_HEAD")
        source = staging / CONTRACT_DIRECTORY_NAME
        if not source.is_dir():
            raise FileNotFoundError(
                f"{repository}@{revision} does not contain {CONTRACT_DIRECTORY_NAME}/"
            )
        # Swap through a rename so a partially written tree is never observed,
        # and so the previous revision stays intact until the new one is ready.
        retired = target.parent / f".{target.name}-retired"
        shutil.rmtree(retired, ignore_errors=True)
        if target.exists():
            target.rename(retired)
        source.rename(target)
        shutil.rmtree(retired, ignore_errors=True)
        # The marker lives inside the tree it describes, so removing the
        # contract directory also removes the claim that it was materialised:
        # a marker that outlived its tree would let the next load report a
        # ready contract that is no longer there.
        (target / REVISION_MARKER_NAME).write_text(f"{revision}\n", encoding="utf-8")
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _materialised_revision(target: Path) -> str | None:
    try:
        return (target / REVISION_MARKER_NAME).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


@contextlib.contextmanager
def _materialisation_lock(plugin_root: Path) -> Iterator[None]:
    """Serialise materialisation between concurrent loaders.

    Hermes may load the plugin from several processes at once, and the swap
    that publishes the contract is a directory rename: without exclusion two
    loaders race on the same staging directory and can publish a tree that is
    missing files. The lock is advisory and process-wide, so it also covers
    the case where two Hermes processes start at the same moment.
    """
    if fcntl is None:  # pragma: no cover - non-POSIX fallback
        yield
        return
    plugin_root.mkdir(parents=True, exist_ok=True)
    handle = os.open(plugin_root / LOCK_FILE_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            os.close(handle)


def _is_ready(root: Path, probes: tuple[str, ...]) -> bool:
    return root.is_dir() and all(path.is_file() for path in _probe_paths(root, probes))


def _failure_reason(pin: Mapping[str, Any], exc: BaseException) -> str:
    """An operator-facing reason: what was attempted, and what to do next."""
    if isinstance(exc, subprocess.CalledProcessError):
        output = (exc.stderr or exc.stdout or "").strip().splitlines()
        detail = output[-1].strip() if output else f"git 退出码 {exc.returncode}"
    else:
        detail = str(exc).strip() or exc.__class__.__name__
    return (
        f"无法获取协议契约：仓库 {pin['repository']} 的提交 {pin['revision']} 拉取失败（{detail}）。"
        f"请检查网络连通性；离线部署可先放置契约目录，"
        f"或用环境变量 {CONTRACT_ROOT_ENV} 指向已就位的契约根目录。"
    )


def _resolve_from_environment() -> ContractResolution | None:
    """Honour an operator-supplied contract root before touching the network.

    The pin file is not consulted here on purpose: an offline bundle is a
    legitimate deployment that never carries one.
    """
    supplied = os.environ.get(CONTRACT_ROOT_ENV, "").strip()
    if not supplied:
        return None
    root = Path(supplied).expanduser()
    if _is_ready(root, DEFAULT_PROBES):
        return ContractResolution(root=root, pinned_ref=None, source="env", reason=None)
    return ContractResolution(
        root=None, pinned_ref=None, source="unavailable",
        reason=(
            f"{CONTRACT_ROOT_ENV} 指向的目录不是可用的契约根：{root}；"
            f"需要其中同时存在 {' 与 '.join(DEFAULT_PROBES)}。"
        ),
    )


def resolve_contract_root(plugin_root: Path, *, force: bool = False) -> ContractResolution:
    from_environment = _resolve_from_environment()
    if from_environment is not None:
        return from_environment

    pin_error: PinError | None = None
    try:
        pin = _read_pin(plugin_root)
    except PinError as exc:
        # A plugin whose pin is unusable still loads, so the host stays
        # startable and the operator gets a stated reason instead of a
        # traceback; the Gateway itself refuses to serve without the contract.
        pin_error = exc
        pin = {"repository": "", "revision": "", "probes": DEFAULT_PROBES}
    root = plugin_root / CONTRACT_DIRECTORY_NAME

    def already_materialised() -> bool:
        return (
            not force
            and _is_ready(root, pin["probes"])
            and _materialised_revision(root) == pin["revision"]
        )

    if pin_error is not None:
        return ContractResolution(
            root=None, pinned_ref=None, source="unavailable", reason=str(pin_error),
        )
    if already_materialised():
        return ContractResolution(
            root=root, pinned_ref=pin["revision"], source="cached", reason=None,
        )
    with _materialisation_lock(plugin_root):
        # Re-checked under the lock: a concurrent loader may have published the
        # pinned revision while this one was waiting, and re-fetching it would
        # be both wasteful and a chance to observe a torn tree.
        if already_materialised():
            return ContractResolution(
                root=root, pinned_ref=pin["revision"], source="cached", reason=None,
            )
        try:
            _checkout(pin["repository"], pin["revision"], root)
        except (subprocess.CalledProcessError, OSError) as exc:
            return ContractResolution(
                root=None, pinned_ref=pin["revision"], source="unavailable",
                reason=_failure_reason(pin, exc),
            )
        if not _is_ready(root, pin["probes"]):
            return ContractResolution(
                root=None, pinned_ref=pin["revision"], source="unavailable",
                reason=(
                    f"契约资产不完整：{pin['repository']}@{pin['revision']} "
                    f"缺少 {'、'.join(pin['probes'])}"
                ),
            )
    return ContractResolution(root=root, pinned_ref=pin["revision"], source="pin", reason=None)