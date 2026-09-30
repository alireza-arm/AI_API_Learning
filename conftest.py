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

import tempfile

import pytest


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory(prefix="pytest_reconciliation_") as path:
        yield path
