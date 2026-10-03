"""STAGE 17 — Cross-process concurrency hardening tests.

Demonstrates and guards against the real production bug found during the
production-readiness review:

    The old _operation_store_lock() was an O_EXCL lock *file* whose
    "stale recovery" deleted the lock file whenever its mtime looked old,
    even while a live process still held it.  A second process could then
    recreate the lock file and enter the critical section concurrently,
    breaking mutual exclusion for operation claims (duplicate STARTED
    records / double side-effects).

The fix routes the lock through memory_storage.interprocess_lock
(fcntl.flock on POSIX / msvcrt.locking on Windows), which is owned by the
OS file handle and cannot be stolen by deleting a file.

These tests spawn REAL subprocesses so the locking is exercised across
process boundaries, not just across threads.

Run standalone:      python3 concurrency_runtime_test.py
Run under pytest:    pytest concurrency_runtime_test.py
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time

BASE = os.path.dirname(os.path.abspath(__file__))


def _run_worker(tmp_dir, code, timeout=60):
    """Run `code` in a fresh interpreter with cwd=tmp_dir."""
    env = dict(os.environ)
    env["PYTHONPATH"] = BASE
    proc = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=tmp_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc


# ---------------------------------------------------------------------------
# Test 1: N concurrent processes claiming the SAME operation key must
# produce exactly ONE fresh claim (created==True); every other process
# must observe the already-STARTED record instead of racing into the store.
# Under the old O_EXCL-with-stale-delete lock this intermittently produced
# duplicate STARTED rows / lost updates.
# ---------------------------------------------------------------------------

_CLAIM_WORKER = """
    import json
    import memory_integrity as mi

    payload = {"memory_id": "mem_conc_1", "text": "shared claim"}
    record, created = mi.begin_operation("MEMORY_ADD", payload)
    print(json.dumps({"operation_id": record["operation_id"], "created": created}))
"""


def test_concurrent_claims_single_winner():
    workers = 8
    results = []
    with tempfile.TemporaryDirectory(prefix="conc_claim_") as tmp:
        procs = []
        for _ in range(workers):
            env = dict(os.environ)
            env["PYTHONPATH"] = BASE
            p = subprocess.Popen(
                [sys.executable, "-c", textwrap.dedent(_CLAIM_WORKER)],
                cwd=tmp, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            procs.append(p)
        for p in procs:
            out, err = p.communicate(timeout=90)
            assert p.returncode == 0, f"worker crashed: {err}"
            results.append(json.loads(out.strip().splitlines()[-1]))

        created_flags = [r["created"] for r in results]
        winners = sum(1 for c in created_flags if c)
        assert winners == 1, f"expected exactly one fresh claim, got {winners}: {results}"

        # The durable store must contain exactly one operation record.
        store_path = os.path.join(tmp, "memory_operations.json")
        with open(store_path, "r", encoding="utf-8") as fh:
            store = json.load(fh)
        ops = store.get("operations", [])
        assert len(ops) == 1, f"duplicate operation records leaked: {ops}"
        # All losers observed the same logical operation identity.
        ids = {r["operation_id"] for r in results}
        assert len(ids) == 1, f"processes disagreed on operation_id: {ids}"
    print("PASS: concurrent claims elect exactly one winner (cross-process)")


# ---------------------------------------------------------------------------
# Test 2: crash-safety of the new lock.  If a lock holder dies hard
# (SIGKILL-style exit mid-critical-section), the OS releases the advisory
# lock with the handle, so the next process must acquire it without any
# stale-file deletion dance.  The OLD design needed OPERATION_LOCK_STALE
# _SECONDS (120s) before another process could break in; the new design
# recovers instantly and safely.
# ---------------------------------------------------------------------------

_HOLD_THEN_DIE = """
    import os, sys
    from memory_storage import interprocess_lock
    import memory_integrity as mi

    lock_path = os.path.abspath(mi.OPERATION_LOCK_FILE)
    handle = open(lock_path, 'a+b') if False else None
    import contextlib
    cm = interprocess_lock(lock_path, timeout_seconds=5)
    cm.__enter__()
    # Signal readiness, then die WITHOUT releasing explicitly.
    print('LOCKED', flush=True)
    os._exit(9)
"""


def test_crashed_holder_releases_lock_immediately():
    with tempfile.TemporaryDirectory(prefix="conc_crash_") as tmp:
        env = dict(os.environ)
        env["PYTHONPATH"] = BASE
        dead = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent(_HOLD_THEN_DIE)],
            cwd=tmp, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        first_line = dead.stdout.readline().strip()
        assert first_line == "LOCKED", f"holder did not report lock: {first_line!r}"
        dead.wait(timeout=10)
        assert dead.returncode == 9

        # Now a fresh process must be able to claim within ~seconds,
        # proving the OS released the lock when the handle died.
        t0 = time.monotonic()
        proc = _run_worker(tmp, """
            import memory_integrity as mi
            record, created = mi.begin_operation("MEMORY_ADD", {"memory_id": "x", "text": "t"})
            print("OK", created)
        """, timeout=30)
        elapsed = time.monotonic() - t0
        assert proc.returncode == 0, f"post-crash claim failed: {proc.stderr}"
        assert "OK True" in proc.stdout
        assert elapsed < 15, f"recovery took {elapsed:.1f}s (stale-delete behavior returned)"
    print("PASS: crashed lock holder releases lock instantly via OS handle ownership")


# ---------------------------------------------------------------------------
# Test 3: concurrent DIFFERENT operations all persist, none lost.
# Lock must serialize writes, not merely avoid exceptions.
# ---------------------------------------------------------------------------

_MULTI_WORKER = """
    import json, os
    import memory_integrity as mi
    idx = int(os.environ["WORKER_IDX"])
    payload = {"memory_id": "mem_" + str(idx), "text": "op " + str(idx)}
    record, created = mi.begin_operation("MEMORY_ADD", payload)
    mi.complete_operation(record["operation_key"], result_data={"idx": idx})
    print(json.dumps(created))
"""


def test_concurrent_distinct_operations_all_persist():
    n = 6
    with tempfile.TemporaryDirectory(prefix="conc_multi_") as tmp:
        procs = []
        for i in range(n):
            env = dict(os.environ)
            env["PYTHONPATH"] = BASE
            env["WORKER_IDX"] = str(i)
            p = subprocess.Popen(
                [sys.executable, "-c", textwrap.dedent(_MULTI_WORKER)],
                cwd=tmp, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            procs.append(p)
        for i, p in enumerate(procs):
            out, err = p.communicate(timeout=90)
            assert p.returncode == 0, f"worker {i} crashed: {err}"

        with open(os.path.join(tmp, "memory_operations.json"), "r", encoding="utf-8") as fh:
            store = json.load(fh)
        ops = store.get("operations", [])
        assert len(ops) == n, f"lost updates: expected {n}, got {len(ops)}"
        statuses = {o["status"] for o in ops}
        assert statuses == {"COMPLETED"}, f"not all completed: {statuses}"
        keys = {o["operation_key"] for o in ops}
        assert len(keys) == n, "operation keys collided"
    print("PASS: concurrent distinct operations all persist without lost updates")


# ---------------------------------------------------------------------------
# Test 4: lock file is never deleted while another process holds it.
# Directly targets the old failure mode (mtime-based stale removal).
# ---------------------------------------------------------------------------

def test_lock_file_survives_stale_mtime():
    with tempfile.TemporaryDirectory(prefix="conc_mtime_") as tmp:
        env = dict(os.environ)
        env["PYTHONPATH"] = BASE
        code = """
            import os, time
            import memory_integrity as mi
            from memory_storage import interprocess_lock

            lock_path = os.path.abspath(mi.OPERATION_LOCK_FILE)
            with interprocess_lock(lock_path, timeout_seconds=5):
                # Age the lock file far beyond the old 120s stale threshold.
                old = time.time() - 10_000
                os.utime(lock_path, (old, old))
                # While we still hold the OS lock, another claim inside THIS
                # process's nested path must block-and-wait, not steal.
                import threading
                order = []
                def second():
                    mi.begin_operation("MEMORY_ADD", {"memory_id": "m2", "text": "t"})
                    order.append("second-done")
                th = threading.Thread(target=second)
                th.start()
                time.sleep(0.5)
                assert not order, "nested claim entered while lock held"
                order.append("holder-exiting")
                th_join = th
            th_join.join(30)
            assert order == ["holder-exiting", "second-done"], order
            assert os.path.exists(lock_path), "lock file must persist (no delete race)"
            print("OK")
        """
        proc = _run_worker(tmp, code, timeout=60)
        assert proc.returncode == 0, f"failed: {proc.stderr}"
        assert "OK" in proc.stdout
    print("PASS: aged lock file is NOT stolen while held; persists after release")


def main():
    tests = [
        test_concurrent_claims_single_winner,
        test_crashed_holder_releases_lock_immediately,
        test_concurrent_distinct_operations_all_persist,
        test_lock_file_survives_stale_mtime,
    ]
    for t in tests:
        t()
    print("CONCURRENCY_RUNTIME_TEST_PASS")


if __name__ == "__main__":
    main()
