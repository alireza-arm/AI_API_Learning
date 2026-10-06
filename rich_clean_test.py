from channel_poster import clean_rich_post

PAD = " This sentence only makes the text long enough to pass the minimum length."

GOOD = """## Hooke's law

Stress is proportional to strain: $\\sigma = E\\varepsilon$.

| Material | E (GPa) |
|:--|--:|
| Steel | 200 |
| Aluminium | 70 |

<details><summary>More</summary>

Extra text here, long enough to be a real explanation.

</details>"""

assert clean_rich_post(GOOD) is not None, "good post rejected"
out = clean_rich_post("## T\n\nSee [the site](https://x.com) for more." + PAD)
assert out and "http" not in out and "the site" in out, "link not stripped"
assert clean_rich_post("## T\n\nBroken formula $\\sigma = E here." + PAD) is None, "unclosed $"
assert clean_rich_post("## T\n\n<details><summary>x</summary>text" + PAD) is None, "unbalanced details"
assert clean_rich_post("## T\n\n<script>x</script>" + PAD) is None, "unknown tag"
assert clean_rich_post("## T\n\n| a | b |\n|--|--|\n| 1 | 2 | 3 |\n" + PAD) is None, "bad table"
print("all checks passed")