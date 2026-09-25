import json
import os


# --------------------------------------------------
# Files
# --------------------------------------------------

MEMORY_FILE = "memory.json"


# --------------------------------------------------
# Guess Memory Type
# --------------------------------------------------

def guess_memory_type(text):
    """
    Guess the type of an old memory.
    """

    text_lower = text.lower()

    if (
        "learning" in text_lower
        or "learn" in text_lower
        or "یادگیری" in text_lower
        or "یاد می‌گیر" in text_lower
        or "یاد میگیر" in text_lower
    ):
        return "learning"

    if (
        "use solidworks" in text_lower
        or "uses solidworks" in text_lower
        or "use abaqus" in text_lower
        or "uses abaqus" in text_lower
        or "software" in text_lower
    ):
        return "tool"

    if (
        "goal" in text_lower
        or "هدف" in text_lower
    ):
        return "goal"

    if (
        "project" in text_lower
        or "پروژه" in text_lower
    ):
        return "project"

    return "other"


# --------------------------------------------------
# Migrate
# --------------------------------------------------

def migrate_memory():

    if not os.path.exists(MEMORY_FILE):

        print("memory.json does not exist.")

        return


    # --------------------------------------------------
    # Read old file
    # --------------------------------------------------

    try:

        with open(
            MEMORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

    except Exception as e:

        print(
            f"❌ Error reading memory.json: {e}"
        )

        return


    if not isinstance(data, list):

        print(
            "❌ memory.json does not contain a list."
        )

        return


    # --------------------------------------------------
    # Already migrated?
    # --------------------------------------------------

    if data and isinstance(data[0], dict):

        print(
            "ℹ️ memory.json is already using "
            "the new format."
        )

        return


    # --------------------------------------------------
    # Convert old memories
    # --------------------------------------------------

    new_memories = []


    for item in data:

        # Skip invalid items
        if not isinstance(item, str):
            continue


        text = item.strip()


        if not text:
            continue


        memory_object = {
            "memory": text,
            "type": guess_memory_type(text),
            "importance": 5
        }


        new_memories.append(
            memory_object
        )


    # --------------------------------------------------
    # Remove exact duplicates
    # --------------------------------------------------

    unique_memories = []

    seen = set()


    for item in new_memories:

        normalized = (
            item["memory"]
            .strip()
            .casefold()
        )


        if normalized in seen:
            continue


        seen.add(normalized)

        unique_memories.append(
            item
        )


    # --------------------------------------------------
    # Save new format
    # --------------------------------------------------

    try:

        with open(
            MEMORY_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                unique_memories,
                file,
                ensure_ascii=False,
                indent=4
            )


        print(
            "✅ Memory migration completed."
        )

        print(
            f"Old memories: {len(data)}"
        )

        print(
            f"New memories: {len(unique_memories)}"
        )


    except Exception as e:

        print(
            f"❌ Error saving memory.json: {e}"
        )


# --------------------------------------------------
# Run
# --------------------------------------------------

if __name__ == "__main__":

    migrate_memory()