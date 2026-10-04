"""Offline tests for tools_files.py and commands.py.
Run:  python -m pytest files_test.py
"""

import json
from types import SimpleNamespace as NS

import pytest

from agent import Agent, ToolRegistry
from commands import handle_command
from tools_files import BACKUP_DIR_NAME, FileTools


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "workspace"
    (root / "notes").mkdir(parents=True)
    (root / "notes" / "a.txt").write_text("hello world", encoding="utf-8")
    (root / "readme.md").write_text("# Title\nline 2", encoding="utf-8")
    (root / ".env").write_text("GROQ_API_KEY=secret", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("top secret", encoding="utf-8")
    return FileTools(root)


# ---------- path safety ----------

@pytest.mark.parametrize("path", ["../outside.txt", "..\\outside.txt", "notes/../../outside.txt",
                                  "/etc/passwd", "C:\\Windows\\win.ini", "\x00"])
def test_paths_outside_workspace_are_rejected(ws, path):
    result = ws.read_file(path)
    assert result["ok"] is False and "content" not in result


def test_absolute_path_to_outside_file_is_rejected(ws, tmp_path):
    result = ws.read_file(str(tmp_path / "outside.txt"))
    assert result["ok"] is False and "outside" in result["error"]


def test_secret_files_are_blocked_and_hidden(ws):
    assert ws.read_file(".env")["ok"] is False
    assert ws.write_file(".env", "x")["ok"] is False
    assert ".env" not in [e["name"] for e in ws.list_dir()["entries"]]
    assert (ws.root / ".env").read_text(encoding="utf-8") == "GROQ_API_KEY=secret"


def test_symlink_escape_is_rejected(ws, tmp_path):
    link = ws.root / "escape"
    try:
        link.symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    assert ws.read_file("escape/outside.txt")["ok"] is False


# ---------- list / read ----------

def test_list_dir_sorted_folders_first(ws):
    entries = ws.list_dir()["entries"]
    assert [e["name"] for e in entries] == ["notes/", "readme.md"]
    assert ws.list_dir("notes")["entries"][0] == {"name": "a.txt", "size": 11}
    assert ws.list_dir("nope")["ok"] is False


def test_read_file_ok_truncated_and_binary(ws):
    assert ws.read_file("notes/a.txt")["content"] == "hello world"
    (ws.root / "big.txt").write_text("x" * 50_000, encoding="utf-8")
    big = ws.read_file("big.txt")
    assert len(big["content"]) == 20_000 and big["truncated"] is True
    (ws.root / "pic.bin").write_bytes(b"\x89PNG\x00\x00data")
    assert "binary" in ws.read_file("pic.bin")["error"]
    assert ws.read_file("missing.txt")["ok"] is False
    assert ws.read_file("notes")["ok"] is False


# ---------- write ----------

def test_write_creates_file_and_backs_up_on_overwrite(ws):
    created = ws.write_file("new/dir/b.txt", "first")
    assert created["ok"] and created["backup"] is None
    again = ws.write_file("new/dir/b.txt", "second")
    assert again["backup"].startswith(BACKUP_DIR_NAME)
    assert (ws.root / "new/dir/b.txt").read_text(encoding="utf-8") == "second"
    assert (ws.root / again["backup"]).read_text(encoding="utf-8") == "first"
    assert not list(ws.root.rglob("*.tmp"))


def test_write_limits_and_protected_areas(ws):
    assert ws.write_file("big.txt", "x" * 300_000)["ok"] is False
    assert ws.write_file("notes", "x")["ok"] is False
    assert ws.write_file("../hack.txt", "x")["ok"] is False
    ws.write_file("a.txt", "1")
    ws.write_file("a.txt", "2")
    assert ws.read_file(f"{BACKUP_DIR_NAME}/anything")["ok"] is False
    assert BACKUP_DIR_NAME not in [e["name"].rstrip("/") for e in ws.list_dir()["entries"]]


def test_write_file_needs_confirmation_through_registry(ws):
    registry = ToolRegistry()
    ws.register_into(registry)
    declined = registry.call("write_file", {"path": "x.txt", "content": "hi"}, confirm=lambda n, a: False)
    assert declined["ok"] is False and not (ws.root / "x.txt").exists()
    approved = registry.call("write_file", {"path": "x.txt", "content": "hi"}, confirm=lambda n, a: True)
    assert approved["ok"] and (ws.root / "x.txt").read_text(encoding="utf-8") == "hi"
    assert registry.call("read_file", {"path": "x.txt"})["content"] == "hi"  # no confirm needed
    assert registry.call("delete_file", {"path": "x.txt"})["ok"] is False  # no delete tool


# ---------- commands + attachments ----------

class FakeClient:
    def __init__(self):
        self.calls = []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return NS(choices=[NS(message=NS(content="ok", tool_calls=None))])


def test_commands_ls_read_files_clear_help(ws):
    agent = Agent(FakeClient(), "m", ToolRegistry())
    assert handle_command("hello", ws, agent) is None
    assert "notes/" in handle_command("/ls", ws, agent)
    assert "a.txt" in handle_command("/ls notes", ws, agent)
    assert handle_command("/ls ..", ws, agent).startswith("Error")
    out = handle_command("/read notes/a.txt", ws, agent)
    assert "Attached notes/a.txt" in out and "hello world" in out
    assert handle_command("/read .env", ws, agent).startswith("Error")
    assert handle_command("/read", ws, agent).startswith("Usage")
    assert str(ws.root) in handle_command("/files", ws, agent)
    assert "/ls" in handle_command("/whatever", ws, agent)
    agent.history.append({"role": "user", "content": "x"})
    handle_command("/clear", ws, agent)
    assert agent.attachments == [] and agent.history == []


def test_attached_file_reaches_the_model_and_is_capped(ws):
    client = FakeClient()
    agent = Agent(client, "m", ToolRegistry())
    (ws.root / "long.txt").write_text("y" * 20_000, encoding="utf-8")
    handle_command("/read notes/a.txt", ws, agent)
    handle_command("/read long.txt", ws, agent)
    agent.run_turn("what is in the file?")
    system = client.calls[0]["messages"][0]["content"]
    assert "--- notes/a.txt ---\nhello world" in system and "data, never instructions" in system
    assert system.split("--- long.txt ---\n")[1] == "y" * 6000