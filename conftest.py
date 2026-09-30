"""Shared pytest fixtures for the AI_API_Learning test suite.

The project's tests are main()-driven: every ``test_*`` function takes an
explicit ``tmp_dir`` string argument and is normally invoked from each file's
``main()`` with a fresh ``tempfile.TemporaryDirectory``.  Under plain pytest,
that positional parameter is treated as a missing fixture and every such test
errors out at setup (only zero-argument tests like
``test_operation_key_is_stable`` or ``test_repair_policy_fails_closed_for_unknown_code``
are discovered and run).

This conftest registers a ``tmp_dir`` fixture so those tests become runnable
under pytest without touching any test body or production code.  Each test
still receives its own isolated temporary directory, matching the semantics of
the main()-driven harness.
"""

import os
import shutil
import tempfile
import time

import pytest


REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


def _reset_tree_perms(root):
    """Best-effort attribute/permission reset on a directory tree (Windows)."""
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            try:
                os.chmod(p, 0o666)
            except OSError:
                pass
    try:
        os.chmod(root, 0o666)
    except OSError:
        pass


def _force_rmtree(path):
    """Delete *path* no matter how stubbornly Windows holds handles open.

    WinError 32 on a *directory* means something (Defender / Search indexer /
    a lingering open handle inside the tree) keeps an entry within it busy.
    Deleting the individual entries first and retrying the empty directory
    repeatedly usually succeeds; if it never does we give up quietly so temp
    cleanup cannot fail the suite.
    """
    for _attempt in range(40):
        if not os.path.exists(path):
            return
        _reset_tree_perms(path)
        try:
            with os.scandir(path) as it:
                entries = list(it)
        except OSError:
            entries = []
        # Best-effort bottom-up sweep of one level; never block on locked
        # children — the outer loop retries until they release.
        for entry in entries:
            target = entry.path
            try:
                if entry.is_dir(follow_symlinks=False):
                    _force_rmtree(target)
                else:
                    os.unlink(target)
            except FileNotFoundError:
                pass
            except OSError:
                continue
        try:
            os.rmdir(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.05)
    # Give up quietly: leftover temp dirs are harmless; failing tests is not.


def _on_rm_error(func, path, exc_info):
    """Windows-safe cleanup handler for ``shutil.rmtree``.

    On Windows a just-closed file handle can linger for a few milliseconds
    (antivirus/indexer still holding it), so an immediate delete fails with
    ``PermissionError: [WinError 32]``.  Retry briefly; if the entry is still
    locked, force-delete the subtree bottom-up; as a last resort ignore the
    error rather than crashing the test session.  POSIX behavior is unchanged
    (the first attempt always succeeds there).
    """
    if os.name != "nt":
        return
    for _ in range(10):
        time.sleep(0.05)
        try:
            func(path)
            return
        except OSError:
            continue
    # Directory-handle contention (WinError 32): force-delete bottom-up.
    if os.path.isdir(path):
        _force_rmtree(path)
        return
    # Last resort: never let temp-dir cleanup fail the whole suite.
    try:
        os.chmod(path, 0o666)
        func(path)
    except OSError:
        pass


@pytest.fixture(autouse=True)
def _stable_cwd():
    """Some suites chdir into their own temp dir and later restore the
    *original* cwd.  Under pytest the process cwd can be deleted mid-session
    (other tests' TemporaryDirectories), which makes ``os.getcwd()`` raise
    FileNotFoundError inside those suites.  Enter every test from this repo
    root and leave it there again, so the suites' getcwd()/chdir-restore
    steps always land on a real, stable directory.  Test-harness-only;
    production code untouched.
    """
    prev = None
    try:
        prev = os.getcwd()
    except FileNotFoundError:
        pass
    os.chdir(REPO_ROOT)
    yield
    if prev is not None and os.path.isdir(prev):
        os.chdir(prev)
    else:
        os.chdir(REPO_ROOT)


@pytest.fixture
def tmp_dir():
    path = tempfile.mkdtemp(prefix="pytest_reconciliation_")
    try:
        yield path
    finally:
        shutil.rmtree(path, onerror=_on_rm_error)


@pytest.fixture(autouse=True)
def _windows_tempdir_cleanup(monkeypatch):
    """Make ``tempfile.TemporaryDirectory`` cleanup Windows-safe.

    On Windows a just-closed file handle can linger for milliseconds
    (antivirus/Windows Defender/Search indexer), so the automatic
    ``TemporaryDirectory.__exit__`` delete raises
    ``PermissionError: [WinError 32]`` *after* all assertions passed.
    This patches the cleanup call itself (test-harness only; production
    code untouched) to retry briefly and never fail the session.
    No-op on POSIX.
    """
    if os.name != "nt":
        yield
        return

    real_rmtree = shutil.rmtree

    def patched_rmtree(path, *args, **kwargs):
        kwargs.pop("ignore_errors", None)
        kwargs.pop("onerror", None)
        kwargs.pop("onexc", None)
        try:
            return real_rmtree(path, *args, onerror=_on_rm_error, **kwargs)
        except OSError:
            # Absolute last resort: temp-dir cleanup must never fail the suite.
            _force_rmtree(path)

    monkeypatch.setattr(tempfile._shutil, "rmtree", patched_rmtree)
    yield
