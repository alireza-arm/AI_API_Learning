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
import tempfile

import pytest


REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


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
    with tempfile.TemporaryDirectory(prefix="pytest_reconciliation_") as path:
        yield path
