"""Slash commands typed by the user (work with any model, no tool calling needed)."""

HELP = """Commands:
  /ls [folder]   list files in the workspace
  /read <file>   show a file and attach it to your next questions
  /files         show the workspace folder
  /clear         drop attached files and this chat's short-term history
  /help          show this help
  /exit          quit"""


def handle_command(text, files, agent):
    """Return the text to print, or None if `text` is not a command."""
    if not text.startswith("/"):
        return None
    command, _, argument = text.partition(" ")
    argument = argument.strip()

    if command == "/ls":
        result = files.list_dir(argument or ".")
        if not result["ok"]:
            return f"Error: {result['error']}"
        lines = [f"  {e['name']}" + (f"  ({e['size']} bytes)" if e["size"] is not None else "")
                 for e in result["entries"]]
        if result["truncated"]:
            lines.append("  ... (list truncated)")
        return f"{result['path']}/\n" + ("\n".join(lines) or "  (empty)")

    if command == "/read":
        if not argument:
            return "Usage: /read <file>"
        result = files.read_file(argument)
        if not result["ok"]:
            return f"Error: {result['error']}"
        agent.attach(result["path"], result["content"])
        note = " (truncated)" if result["truncated"] else ""
        preview = "\n".join(result["content"].splitlines()[:15])
        return (f"Attached {result['path']}{note}. Ask your question about it now.\n"
                f"--- preview ---\n{preview}")

    if command == "/files":
        return f"Workspace: {files.root}"

    if command == "/clear":
        agent.attachments.clear()
        agent.history.clear()
        return "Cleared attached files and short-term history."

    return HELP