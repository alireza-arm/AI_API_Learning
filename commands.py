"""Slash commands used by the terminal and Telegram front-end."""

HELP = """Commands:
  /start         open the bot menu
  /help          show all commands
  /ls [folder]   list files in the workspace
  /read <file>   attach a file to your next questions
  /files         show the workspace folder
  /clear         clear attached files and short-term chat history
  /preview       generate a channel draft (not published)
  /approve       publish the waiting draft exactly as reviewed
  /skip          discard the waiting draft
  /redraft       replace the waiting draft
  /post_now      publish now (draft or fresh post)
  /post_pause    pause scheduled posting
  /post_resume   resume scheduled posting
  /post_status   show channel status"""


def handle_command(text, files, agent):
    """Return command output, or None when the text is not a known command."""
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
        return f"Attached {result['path']}{note}. Ask your question about it now.\n--- preview ---\n{preview}"

    if command == "/files":
        return f"Workspace: {files.root}"

    if command == "/clear":
        agent.attachments.clear()
        agent.history.clear()
        return "Cleared attached files and short-term history."

    if command in {"/start", "/help"}:
        return HELP
    return HELP
