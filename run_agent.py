"""Run the agent in the terminal:  python run_agent.py

Needs GROQ_API_KEY in .env (same as test_ai.py).
"""

import os

from dotenv import load_dotenv
from groq import Groq

from agent import Agent, ToolRegistry
from tools_memory import MemoryTools

MODEL_NAME = "openai/gpt-oss-20b"


def build_agent():
    load_dotenv()
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY was not found.")

    memory = MemoryTools()
    registry = ToolRegistry()
    memory.register_into(registry)

    def context_provider(user_text):
        results = memory.backend.search_memory(user_text, max_results=3, threshold=0.4)
        return "\n".join(f"- {r['memory']}" for r in results) or None

    def on_event(kind, name, args, result):
        print(f"  [tool] {name}({args}) -> {result}")

    def confirm(name, args):
        return input(f"  Allow {name}({args})? [y/N] ").strip().lower() == "y"

    return Agent(Groq(api_key=api_key), MODEL_NAME, registry,
                 context_provider=context_provider,
                 confirm=confirm, on_event=on_event)


def main():
    agent = build_agent()
    print("Agent ready. Type /exit to quit.")
    while True:
        text = input("\nYou: ").strip()
        if not text:
            continue
        if text == "/exit":
            break
        print("\nAI:", agent.run_turn(text))


if __name__ == "__main__":
    main()
