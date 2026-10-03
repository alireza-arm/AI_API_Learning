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
3. **Entry point** – `run_agent.py` (Groq, model `openai/gpt-oss-20b`, key in `.env`).

## Existing system (unchanged)
- `long_term_memory.py`, `memory_entities.py`, `memory_*`: storage, embeddings
  (sentence-transformers), lifecycle, conflicts, graph.
- `test_ai.py`: the old pipeline-style chat (several LLM calls per message).

## Tests
- `agent_loop_test.py`: offline (fake client + fake backend).
  Run: `python -m pytest agent_loop_test.py`

## Planned next
- File tools (allowlisted folder, read-only first, writes need confirmation)
- Telegram bot (whitelist user ID) + scheduler for hourly posts
- Gmail (read-only OAuth)
- Move the old analyze_* pipeline into a periodic background job
