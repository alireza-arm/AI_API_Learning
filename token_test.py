import json
import os
from transformers import AutoTokenizer

MODEL_NAME = "openai/gpt-oss-20b"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

MAX_CONTEXT_TOKENS = 150

def load_long_term_memory():
    if not os.path.exists("memory.json"):
        return {}

    with open("memory.json", "r", encoding="utf-8") as file:
        return json.load(file)

def count_tokens(messages):
    encoded_chat = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=False
    )

    return len(encoded_chat["input_ids"])


def check_budget(messages):
    used_tokens = count_tokens(messages)
    remaining_tokens = MAX_CONTEXT_TOKENS - used_tokens

    print("\n--- Token Budget ---")
    print("Maximum:", MAX_CONTEXT_TOKENS)
    print("Used:", used_tokens)
    print("Remaining:", remaining_tokens)

    if remaining_tokens < 0:
        print("WARNING: Context limit exceeded!")
    else:
        print("Context is within the limit.")

SHORT_TERM_TURNS = 2

def save_long_term_memory(memory):
    with open("memory.json", "w", encoding="utf-8") as file:
        json.dump(memory, file, ensure_ascii=False, indent=4)

def get_short_term_memory(messages):

    system_message = messages[0]


    conversation_messages = messages[1:]

    messages_to_keep = SHORT_TERM_TURNS * 2

    recent_messages = conversation_messages[-messages_to_keep:]

    return [system_message] + recent_messages


messages = [
    {
        "role": "system",
        "content": "You are a helpful assistant."
    },

    {
        "role": "user",
        "content": "Hello, my name is Ali."
    },

    {
        "role": "assistant",
        "content": "Nice to meet you, Ali!"
    },

    {
        "role": "user",
        "content": "I study mechanical engineering."
    },

    {
        "role": "assistant",
        "content": "That is a great field."
    },

    {
        "role": "user",
        "content": "I am learning Abaqus."
    },

    {
        "role": "assistant",
        "content": "Abaqus is used for finite element analysis."
    },

    {
        "role": "user",
        "content": "I also use SolidWorks."
    },

    {
        "role": "assistant",
        "content": "SolidWorks is useful for mechanical design."
    }
]

long_term_memory = load_long_term_memory()

print("\n--- Long-Term Memory ---")
print(long_term_memory)

long_term_memory = load_long_term_memory()

long_term_memory["country"] = "Germany"

save_long_term_memory(long_term_memory)

check_budget(messages)

short_term_memory = get_short_term_memory(messages)

print("\n--- Short-Term Memory ---")

for message in short_term_memory:
    print(f"{message['role']}: {message['content']}")

old_tokens = count_tokens(messages)
new_tokens = count_tokens(short_term_memory)

print("\n--- Memory Comparison ---")
print("Original Tokens:", old_tokens)
print("Short-Term Tokens:", new_tokens)
print("Saved Tokens:", old_tokens - new_tokens)    