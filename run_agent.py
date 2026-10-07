"""Run the agent in the terminal:  python run_agent.py

By default it talks to a local Ollama model (llama3.2:3b); no internet needed.
To use Groq instead, put these in .env:
    LLM_PROVIDER=groq
    GROQ_API_KEY=...
"""

import os

from dotenv import load_dotenv

from agent import SYSTEM_PROMPT, SYSTEM_PROMPT_AUTO, Agent, ToolRegistry
from auto_memory import AutoMemory
from commands import handle_command
from tools_files import FileTools
from tools_memory import MemoryTools

GROQ_MODEL = "openai/gpt-oss-20b"


def make_client():
    """LLM_PROVIDER=ollama (default), groq, or 9router.
    Optional: OLLAMA_MODEL / GROQ_MODEL / ROUTER_MODEL in .env."""
    provider = os.getenv("LLM_PROVIDER", "ollama").lower()

    if provider == "groq":
        from groq import Groq
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY was not found.")
        return Groq(api_key=api_key), GROQ_MODEL, provider

    if provider == "9router":
        from openai import OpenAI
        base_url = os.getenv("NINEROUTER_URL", "http://localhost:20128/v1").strip()
        api_key = os.getenv("NINEROUTER_KEY", "").strip() or "not-needed"
        model = os.getenv("ROUTER_MODEL", "claude-sonnet-4-5").strip()
        return OpenAI(base_url=base_url, api_key=api_key), model, provider

    from ollama_client import OllamaClient
    return OllamaClient(), os.getenv("OLLAMA_MODEL", "llama3.2:3b"), provider


def build_agent(interactive=True):
    """interactive=False (used by the Telegram bot): never asks via input(); writes are denied."""
    load_dotenv()
    client, model, provider = make_client()
    # "auto": code saves memories (reliable with small local models, no tool calling).
    # "tools": the model calls remember/recall itself (needs a strong model, e.g. Groq).
    mode = os.getenv("MEMORY_MODE", "auto" if provider == "ollama" else "tools").lower()
    print(f"Provider: {provider}, model: {model}, memory mode: {mode}")

    memory = MemoryTools()
    files = FileTools()
    registry = ToolRegistry()
    before_turn = None
    system_prompt = SYSTEM_PROMPT_AUTO
    if mode == "tools":
        memory.register_into(registry)
        system_prompt = SYSTEM_PROMPT
    else:
        before_turn = AutoMemory(client, model, memory)

    def on_event(kind, name, args, result):
        if kind == "tool":
            print(f"  [tool] {name}({args}) -> {result}")
        elif kind == "auto_memory":
            print(f"  [memory] saved: {name}")
        elif kind == "warning":
            print(f"  [warning] {name}: {args}")
        elif kind == "retry":
            print(f"  [retry] API error {name}, attempt {args}...")

    def confirm(name, args):
        if not interactive:
            return False
        shown = {k: (str(v) if len(str(v)) <= 120 else f"{str(v)[:120]}... ({len(str(v))} chars)")
                 for k, v in args.items()}
        return input(f"  Allow {name}({shown})? [y/N] ").strip().lower() == "y"

    # Real file tools need a model that is good at tool calling (not a 3B model).
    if mode == "tools" or os.getenv("FILE_TOOLS", "off").lower() == "on":
        files.register_into(registry)

    agent = Agent(client, model, registry, system_prompt=system_prompt,
                  before_turn=before_turn,
                  context_provider=memory.context_for,
                  confirm=confirm, on_event=on_event)
    return agent, files


def main():
    agent, files = build_agent()
    print(f"Workspace: {files.root}")
    print("Agent ready. Type /help for commands, /exit to quit.")
    while True:
        text = input("\nYou: ").strip()
        if not text:
            continue
        if text == "/exit":
            break
        output = handle_command(text, files, agent)
        if output is not None:
            print(output)
            continue
        try:
            print("\nAI:", agent.run_turn(text))
        except Exception as exc:
            print(f"\n[error] {type(exc).__name__}: {exc}")
            print("The request failed. Try again, or check your connection / that Ollama is running.")


if __name__ == "__main__":
    main()