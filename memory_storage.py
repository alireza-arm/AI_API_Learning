import json
import os
import shutil
import tempfile
import contextlib
import time
from typing import Any, Callable, Optional, Type


DEFAULT_BACKUP_SUFFIX = ".bak"


@contextlib.contextmanager
def interprocess_lock(path: str, timeout_seconds: float = 30.0, poll_seconds: float = 0.05):
    """Acquire a small cross-process filesystem lock.

    The lock is advisory and scoped to the supplied lock-file path. It uses
    msvcrt on Windows and fcntl on POSIX, while keeping the lock file itself
    persistent so concurrent processes coordinate without modifying the
    protected JSON document directly.
    """
    path = os.path.abspath(str(path))
    directory = os.path.dirname(path) or os.getcwd()
    os.makedirs(directory, exist_ok=True)
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    handle = open(path, "a+b")
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"0")
        handle.flush()
    acquired = False
    try:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"timed out acquiring interprocess lock: {path}")
                time.sleep(max(0.01, float(poll_seconds)))
        yield handle
    finally:
        if acquired:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        handle.close()


def _default_value(factory: Any):
    if callable(factory):
        return factory()
    return factory


def _read_json_file(path: str):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def _is_valid_json_file(path: str, expected_type: Optional[Type] = None) -> bool:
    try:
        data = _read_json_file(path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False

    if expected_type is not None and not isinstance(data, expected_type):
        return False

    return True


def _restore_backup(path: str, backup_path: str) -> bool:
    directory = os.path.dirname(os.path.abspath(path)) or os.getcwd()
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".restore.tmp",
            prefix=f".{os.path.basename(path)}.",
            dir=directory,
            delete=False,
        ) as temp_file:
            temp_path = temp_file.name
            with open(backup_path, "rb") as backup_file:
                shutil.copyfileobj(backup_file, temp_file)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        os.replace(temp_path, path)
        temp_path = None
        return True
    except OSError:
        return False
    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass


def load_json_document(
    path: str,
    default_factory: Any,
    expected_type: Optional[Type] = None,
    backup_suffix: str = DEFAULT_BACKUP_SUFFIX,
):
    """Load JSON safely, falling back to the last known-good backup.

    A malformed primary file is never silently treated as authoritative. If a
    valid backup exists, it is restored to the primary path before returning.
    """
    backup_path = f"{path}{backup_suffix}"

    if os.path.exists(path):
        try:
            data = _read_json_file(path)
            if expected_type is None or isinstance(data, expected_type):
                return data
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            pass

    if os.path.exists(backup_path):
        try:
            backup_data = _read_json_file(backup_path)
            if expected_type is None or isinstance(backup_data, expected_type):
                _restore_backup(path, backup_path)
                return backup_data
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            pass

    return _default_value(default_factory)


def save_json_document(
    path: str,
    data: Any,
    backup_suffix: str = DEFAULT_BACKUP_SUFFIX,
    indent: int = 2,
) -> str:
    """Persist JSON atomically and retain the last known-good version.

    The backup is updated only when the current primary file contains valid
    JSON. This prevents a corrupt primary file from destroying the good backup.
    """
    directory = os.path.dirname(os.path.abspath(path)) or os.getcwd()
    os.makedirs(directory, exist_ok=True)

    backup_path = f"{path}{backup_suffix}"

    if os.path.exists(path) and _is_valid_json_file(path):
        try:
            shutil.copy2(path, backup_path)
        except OSError:
            # The atomic primary write can still proceed even if the backup
            # copy fails. The caller receives a successful save if replacement
            # succeeds.
            pass

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".tmp",
            prefix=f".{os.path.basename(path)}.",
            dir=directory,
            delete=False,
        ) as temp_file:
            temp_path = temp_file.name
            json.dump(data, temp_file, ensure_ascii=False, indent=indent)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        os.replace(temp_path, path)
        temp_path = None
        return path
    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass
