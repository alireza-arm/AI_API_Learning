"""Check what is stored in memory and how the search scores Persian vs English queries.
Run (in the project folder):  py debug_memory.py
"""
import long_term_memory as lt

memory = lt.get_memory()
print(f"Stored active memories: {len(memory)}")
for item in memory[:10]:
    print("  -", item.get("memory"))

queries = ["اسم من چیه و چی میخونم؟", "what is the user's name and field of study"]
for q in queries:
    print(f"\nQuery: {q}")
    results = lt.search_memory(q, max_results=3, threshold=0.0)
    if not results:
        print("  (no results)")
    for r in results:
        print(f"  similarity={r['similarity']}  {r['memory']}")
