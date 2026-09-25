import os
import json
import shutil

from groq import Groq
from dotenv import load_dotenv


# --------------------------------------------------
# 1. Connect to Groq
# --------------------------------------------------

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    raise ValueError(
        "GROQ_API_KEY is not set."
    )

client = Groq(
    api_key=api_key
)


# --------------------------------------------------
# 2. Settings
# --------------------------------------------------

MODEL_NAME = "openai/gpt-oss-20b"

MEMORY_FILE = "memory.json"
BACKUP_FILE = "memory_backup.json"


# --------------------------------------------------
# 3. Load Memory
# --------------------------------------------------

def load_memory():

    if not os.path.exists(MEMORY_FILE):
        return []

    try:

        with open(
            MEMORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if not isinstance(data, list):
            return []

        return data

    except Exception as e:

        print(
            f"❌ Error reading memory.json: {e}"
        )

        return []


# --------------------------------------------------
# 4. Save Memory
# --------------------------------------------------

def save_memory(memory):

    try:

        with open(
            MEMORY_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                memory,
                file,
                ensure_ascii=False,
                indent=4
            )

        return True

    except Exception as e:

        print(
            f"❌ Error saving memory.json: {e}"
        )

        return False


# --------------------------------------------------
# 5. Normalize old format
# --------------------------------------------------

def normalize_memory(memory):

    normalized = []

    for item in memory:

        # Old format
        if isinstance(item, str):

            normalized.append(
                {
                    "memory": item,
                    "type": "other",
                    "importance": 5
                }
            )

        # New format
        elif isinstance(item, dict):

            text = item.get(
                "memory",
                ""
            )

            if not text:
                continue

            normalized.append(
                {
                    "memory": str(text),
                    "type": str(
                        item.get(
                            "type",
                            "other"
                        )
                    ),
                    "importance": int(
                        item.get(
                            "importance",
                            5
                        )
                    )
                }
            )

    return normalized


# --------------------------------------------------
# 6. Clean Memories using AI
# --------------------------------------------------

def cleanup_memories(memories):

    numbered_memories = "\n".join(

        f"{i}. "
        f"Memory: {item['memory']} | "
        f"Type: {item['type']} | "
        f"Importance: {item['importance']}"

        for i, item in enumerate(
            memories,
            start=1
        )
    )


    prompt = f"""
You are a LONG-TERM MEMORY CLEANUP MANAGER.

The following are memories stored for one user:

{numbered_memories}


Your task is to clean and consolidate these memories.


RULES:

1. Find memories that refer to the same fact, skill,
   preference, project, goal, or user information.

2. Merge semantically similar memories into ONE memory.

3. Do not merge unrelated information.

4. Keep the most complete and useful version.

5. Do not invent information.

6. Keep each memory short.

7. Preserve important information.

8. If two memories describe the same subject but one
   contains additional useful information, combine them.

9. Keep importance between 0 and 5.

10. Keep one type for each memory.

11. Valid types are:

identity
skill
learning
goal
project
preference
tool
constraint
other

12. Output ONLY valid JSON.

13. The result must be a JSON array.

14. Every item must have exactly:

- memory
- type
- importance


Example:

Input:

"learning Abaqus"
"User is learning Abaqus."
"working more on Abaqus"

Output:

[
    {{
        "memory": "User is learning Abaqus.",
        "type": "learning",
        "importance": 5
    }}
]
"""


    try:

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You clean and consolidate "
                        "long-term user memories."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0
        )


        result = (
            response
            .choices[0]
            .message
            .content
            .strip()
        )


        # --------------------------------------------------
        # Remove markdown code blocks
        # --------------------------------------------------

        if result.startswith("```"):

            result = result.replace(
                "```json",
                ""
            )

            result = result.replace(
                "```",
                ""
            )

            result = result.strip()


        cleaned = json.loads(
            result
        )


        if not isinstance(
            cleaned,
            list
        ):
            raise ValueError(
                "AI did not return a JSON list."
            )


        # --------------------------------------------------
        # Validate AI output
        # --------------------------------------------------

        valid_types = {
            "identity",
            "skill",
            "learning",
            "goal",
            "project",
            "preference",
            "tool",
            "constraint",
            "other"
        }


        final_memory = []


        for item in cleaned:

            if not isinstance(
                item,
                dict
            ):
                continue


            memory_text = item.get(
                "memory"
            )

            memory_type = item.get(
                "type",
                "other"
            )

            importance = item.get(
                "importance",
                5
            )


            if not memory_text:
                continue


            memory_type = str(
                memory_type
            ).lower()


            if memory_type not in valid_types:
                memory_type = "other"


            try:

                importance = int(
                    importance
                )

            except (
                TypeError,
                ValueError
            ):

                importance = 5


            importance = max(
                0,
                min(
                    5,
                    importance
                )
            )


            final_memory.append(
                {
                    "memory": str(
                        memory_text
                    ).strip(),

                    "type": memory_type,

                    "importance": importance
                }
            )


        return final_memory


    except Exception as e:

        print(
            f"❌ AI cleanup error: {e}"
        )

        return None


# --------------------------------------------------
# 7. Main
# --------------------------------------------------

def main():

    print(
        "Starting memory cleanup..."
    )


    memories = load_memory()


    if not memories:

        print(
            "Memory is empty."
        )

        return


    memories = normalize_memory(
        memories
    )


    print(
        f"Current memories: "
        f"{len(memories)}"
    )


    # --------------------------------------------------
    # Create backup
    # --------------------------------------------------

    try:

        shutil.copyfile(
            MEMORY_FILE,
            BACKUP_FILE
        )

        print(
            f"✅ Backup created: "
            f"{BACKUP_FILE}"
        )

    except Exception as e:

        print(
            f"❌ Could not create backup: {e}"
        )

        return


    # --------------------------------------------------
    # AI Cleanup
    # --------------------------------------------------

    cleaned_memory = cleanup_memories(
        memories
    )


    if cleaned_memory is None:

        print(
            "❌ Cleanup failed."
        )

        print(
            "Original memory.json was not changed."
        )

        return


    # --------------------------------------------------
    # Save cleaned memory
    # --------------------------------------------------

    if save_memory(
        cleaned_memory
    ):

        print(
            "✅ Memory cleanup completed."
        )

        print(
            f"Before: {len(memories)}"
        )

        print(
            f"After:  {len(cleaned_memory)}"
        )


        print(
            "\n--- Cleaned Memories ---"
        )


        for i, item in enumerate(
            cleaned_memory,
            start=1
        ):

            print(
                f"{i}. "
                f"{item['memory']} "
                f"| type: {item['type']} "
                f"| importance: "
                f"{item['importance']}/5"
            )


        print(
            "------------------------"
        )


    else:

        print(
            "❌ Failed to save cleaned memory."
        )


# --------------------------------------------------
# Run
# --------------------------------------------------

if __name__ == "__main__":

    main()