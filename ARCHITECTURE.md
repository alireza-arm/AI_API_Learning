# Architecture

## Goal
A personal AI agent that manages its own long-term memory and can later use
tools (files, Telegram, Gmail). The model decides what to do; code runs the loop.

## Layers
1. **Agent loop** – `agent.py`
   - `Agent.run_turn(text)`: calls the model, executes requested tools, repeats
     (max 6 steps), returns the final answer.
   - `ToolRegistry`: `register(schema, func, needs_confirmation=False)`.
     Dangerous tools set `needs_confirmation=True` and go through `confirm()`.
   - Only user/assistant text is kept between turns; tool traffic is per-turn.
2. **Memory tools** – `tools_memory.py`
   - 6 tools over `long_term_memory.py`: remember, recall, update_memory,
     end_memory, forget, list_recent_memories.
3. **LLM clients** – `ollama_client.py` (local Ollama via httpx, default `llama3.2:3b`)
   or the Groq SDK. Chosen by `LLM_PROVIDER` in `.env` (`ollama` default, or `groq`).
4. **Memory modes** (`MEMORY_MODE` in `.env`)
   - `auto` (default with Ollama): `auto_memory.py` runs a separate JSON-extraction call on
     every user message and saves facts; `MemoryTools.context_for` injects memories into the
     prompt. No tool calling needed (small models are unreliable at it).
   - `tools` (default with Groq): the model calls remember/recall itself.
5. **File access** – `tools_files.py` (workspace-restricted: list_dir, read_file,
   write_file with confirmation + backups, no delete) and `commands.py` (slash commands
   `/ls`, `/read`, `/files`, `/clear`, `/help` that work with any model; `/read` attaches
   a file to the next questions). Workspace: `AGENT_WORKSPACE` in `.env`
   (default `D:\agent_workspace`). Real file *tools* for the model are registered only when
   `MEMORY_MODE=tools` or `FILE_TOOLS=on` (needs a model that is good at tool calling).
6. **Telegram front-end** – `telegram_bot.py` (long polling with httpx, no extra packages).
   Only answers the user id in `TELEGRAM_ALLOWED_USER_ID`, private chats only. Uses
   `TELEGRAM_PROXY` only (system proxy settings are ignored on purpose). The token never
   appears in logs/errors. Same slash commands as the terminal. Writes are denied (no
   interactive confirmation over Telegram yet).
7. **Channel posts** – `channel_poster.py`: one mechanical-engineering post every
   `POST_INTERVAL_HOURS` (default 2) to `TELEGRAM_CHANNEL_ID` (the bot must be a channel admin
   with "Post messages"). Topics rotate; posts are written by calling the model directly with a
   fixed prompt, so agent memory/files are never included. Output is cleaned (no links/markdown)
   and rejected if too short/long or a refusal. State in `post_state.json` (survives restarts,
   no catch-up posts after downtime, retry delay on failure).
   `POST_MODE=review` (default): every interval a draft is sent to the owner and NOTHING is
   published until `/approve` (`/skip` discards, `/redraft` rewrites; the pending draft is stored
   in the state file). `POST_MODE=auto` publishes without review.
   Owner commands in the bot chat: /preview /approve /skip /redraft /post_now /post_pause
   /post_resume /post_status. `py telegram_bot.py --check` also verifies the channel permissions.
8. **Entry point** – `run_agent.py` (`build_agent(interactive=False)` is used by the bot).

## Existing system (unchanged)
- `long_term_memory.py`, `memory_entities.py`, `memory_*`: storage, embeddings
  (sentence-transformers), lifecycle, conflicts, graph.
- `test_ai.py`: the old pipeline-style chat (several LLM calls per message).

## Tests
- `agent_loop_test.py`, `ollama_client_test.py`, `auto_memory_test.py`, `files_test.py`, `telegram_bot_test.py`, `channel_poster_test.py`: offline (fake client/server + fake backend).
  Run: `python -m pytest agent_loop_test.py ollama_client_test.py auto_memory_test.py files_test.py telegram_bot_test.py channel_poster_test.py`

## Recent Changes
- Added OCR fallback for scanned/empty PDFs behind `PDF_OCR=on` flag in `tools_files.py`.
- Added fixed full-width channel footer (`<blockquote expandable><a href="...">...</a></blockquote>`) appended to every rich post after validation in `channel_poster.py`.
- Kept ARCHITECTURE.md up to date.
