import json
import math
import time

from long_term_memory import get_memory
from memory_entities import Memory


EMBEDDING_FILE = "embeddings.json"


# --------------------------------------------------
# Load embeddings
# --------------------------------------------------

def load_embeddings():

    try:
        with open(
            EMBEDDING_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    except FileNotFoundError:

        return {}



# --------------------------------------------------
# Cosine Similarity
# --------------------------------------------------

def cosine_similarity(vec1, vec2):

    if not vec1 or not vec2:
        return 0


    dot = sum(
        a*b
        for a,b in zip(vec1,vec2)
    )


    norm1 = math.sqrt(
        sum(a*a for a in vec1)
    )

    norm2 = math.sqrt(
        sum(a*a for a in vec2)
    )


    if norm1 == 0 or norm2 == 0:
        return 0


    return dot/(norm1*norm2)




# --------------------------------------------------
# Normalize values
# --------------------------------------------------

def normalize(value, max_value):

    if value is None:
        return 0

    return min(
        value/max_value,
        1
    )




# --------------------------------------------------
# Memory score
# --------------------------------------------------

def calculate_memory_score(
        memory,
        similarity
):


    importance = normalize(
        memory.get(
            "importance",
            1
        ),
        5
    )


    confidence = memory.get(
        "confidence",
        0.5
    )


    lifecycle_map = {

        "active":1,
        "aging":0.7,
        "decaying":0.4,
        "archived":0.2

    }


    lifecycle = lifecycle_map.get(
        memory.get(
            "status",
            "active"
        ),
        0.5
    )


    access = normalize(
        memory.get(
            "access_count",
            0
        ),
        20
    )


    timestamp = memory.get(
        "created_at",
        time.time()
    )


    age = time.time() - timestamp


    recency = math.exp(
        -age / (60*60*24*30)
    )



    score = (

        similarity * 0.35

        +

        importance * 0.20

        +

        confidence * 0.15

        +

        lifecycle * 0.10

        +

        access * 0.10

        +

        recency * 0.10

    )


    return round(
        score,
        4
    )




# --------------------------------------------------
# Retrieve memories
# --------------------------------------------------

def retrieve_memories(
        query_embedding,
        top_k=5
):


    memories = get_memory()


    embeddings = load_embeddings()


    results = []



    for memory in memories:


        memory_id = memory.get(
            "memory_id"
        )


        if memory_id not in embeddings:
            continue



        similarity = cosine_similarity(
            query_embedding,
            embeddings[memory_id]
        )


        score = calculate_memory_score(
            memory,
            similarity
        )


        results.append({

            "memory":memory.get(
                "content"
            ),

            "memory_id":memory_id,

            "similarity":round(
                similarity,
                4
            ),

            "importance":memory.get(
                "importance",
                0
            ),

            "confidence":memory.get(
                "confidence",
                0
            ),

            "final_score":score

        })



    results.sort(
        key=lambda x:x["final_score"],
        reverse=True
    )


    return results[:top_k]



# --------------------------------------------------
# Debug
# --------------------------------------------------

if __name__ == "__main__":


    print(
        "Memory Retrieval Engine Ready"
    )