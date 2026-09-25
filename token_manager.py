from transformers import AutoTokenizer
import re


# --------------------------------------------------
# Model
# --------------------------------------------------

MODEL_NAME = "openai/gpt-oss-20b"


# --------------------------------------------------
# Tokenizer
# --------------------------------------------------

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_NAME
)


# --------------------------------------------------
# Normalize Text
# --------------------------------------------------

def normalize_text(text):
    """
    Normalize text for local relevance matching.
    """

    text = str(text).lower().strip()

    # Replace punctuation with spaces
    text = re.sub(
        r"[^\w\s]",
        " ",
        text,
        flags=re.UNICODE
    )

    # Remove extra spaces
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text


# --------------------------------------------------
# Get Words
# --------------------------------------------------

def get_words(text):
    """
    Convert text into a set of words.
    """

    normalized = normalize_text(
        text
    )

    return set(
        normalized.split()
    )


# --------------------------------------------------
# Get Memory Text
# --------------------------------------------------

def get_memory_text(memory_item):
    """
    Extract plain memory text from a memory object.
    """

    if isinstance(
        memory_item,
        dict
    ):

        return str(
            memory_item.get(
                "memory",
                ""
            )
        )

    # Backward compatibility
    return str(
        memory_item
    )


# --------------------------------------------------
# Count Tokens
# --------------------------------------------------

def count_tokens(text):
    """
    Count tokens using the model tokenizer.
    """

    return len(
        tokenizer.encode(
            text,
            add_special_tokens=False
        )
    )


# --------------------------------------------------
# Calculate Relevance
# --------------------------------------------------

def calculate_relevance(
    query,
    memory_item
):
    """
    Calculate local word-overlap relevance.

    Returns a value between 0 and 1.
    """

    query_words = get_words(
        query
    )

    memory_text = get_memory_text(
        memory_item
    )

    memory_words = get_words(
        memory_text
    )


    if not query_words or not memory_words:
        return 0.0


    shared_words = (
        query_words &
        memory_words
    )


    # Number of query words that appear
    # in the memory
    overlap = (
        len(shared_words)
        /
        len(query_words)
    )


    return min(
        1.0,
        overlap
    )


# --------------------------------------------------
# Calculate Retrieval Score
# --------------------------------------------------

def calculate_retrieval_score(
    query,
    memory_item
):
    """
    Combine:

    - relevance to current query
    - long-term importance
    """

    relevance = calculate_relevance(
        query,
        memory_item
    )


    if isinstance(
        memory_item,
        dict
    ):

        importance = memory_item.get(
            "importance",
            0
        )

    else:

        importance = 0


    try:

        importance = int(
            importance
        )

    except (
        TypeError,
        ValueError
    ):

        importance = 0


    importance = max(
        0,
        min(
            5,
            importance
        )
    )


    normalized_importance = (
        importance / 5
    )


    # Relevance has more weight than
    # importance.

    score = (
        relevance * 0.7
        +
        normalized_importance * 0.3
    )


    return score


# --------------------------------------------------
# Build Memory With Token Limit
# --------------------------------------------------

def build_memory_with_token_limit(
    memories,
    max_tokens,
    query=""
):
    """
    Select the most relevant and important memories
    without exceeding max_tokens.
    """

    if not memories:
        return [], 0


    # --------------------------------------------------
    # Score memories
    # --------------------------------------------------

    scored_memories = []


    for item in memories:

        score = calculate_retrieval_score(
            query,
            item
        )


        scored_memories.append(
            (
                score,
                item
            )
        )


    # --------------------------------------------------
    # Sort by retrieval score
    # --------------------------------------------------

    scored_memories.sort(
        key=lambda x: x[0],
        reverse=True
    )


    selected = []

    used_tokens = 0


    # --------------------------------------------------
    # Select memories
    # --------------------------------------------------

    for score, item in scored_memories:

        memory_text = get_memory_text(
            item
        )


        if not memory_text:
            continue


        tokens = count_tokens(
            memory_text
        )


        if (
            used_tokens + tokens
            > max_tokens
        ):
            continue


        selected.append(
            item
        )

        used_tokens += tokens


    return (
        selected,
        used_tokens
    )