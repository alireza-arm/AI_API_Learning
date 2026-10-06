"""One-off check: do rich messages with a table and a formula render?
Run: py rich_test.py            (sends to your private chat)
     py rich_test.py --channel  (sends to TELEGRAM_CHANNEL_ID instead)
"""
import os
import sys

from dotenv import load_dotenv

from telegram_bot import TelegramAPI, TelegramError

MD = r"""## Rich test (markdown)

| Quantity | Symbol | Formula |
|:--:|:-:|:--:|
| Stress | $\sigma$ | $\frac{F}{A}$ |
| Strain | $\varepsilon$ | $\frac{\Delta L}  {L_0}$ |

Hooke's law inline: $\sigma = E\varepsilon$

$$\sigma_{max} = \frac{M c}{I}$$
### Numbered list
1. Draw the free-body diagram
2. Write the equilibrium equations
3. Solve for the unknowns

### Bullet list
- Tension
- Compression
- Shear

### Nested list
1. Loads
   - Static
   - Dynamic
2. Supports
   - Fixed
   - Pinned

### Task list
- [x] Check units
- [ ] Apply safety factor
# Heading 1
## Heading 2
### Heading 3
#### Heading 4
##### Heading 5
###### Heading 6

> Single-line block

> First line of a multi-line block
>
> Second line of a multi-line block

<details>
<summary>More info (tap to expand)</summary>

Extra explanation with **bold** text and a formula $\sigma = E\varepsilon$.

</details>

```python
print("copy me")
```
### Text formatting

**Bold text**

*Italic text*

<u>Underlined text</u>

~~Strikethrough text~~

||Spoiler text||

==Marked text==

Subscript: H<sub>2</sub>O

Superscript: x<sup>2</sup>

All together: **bold *italic* ~~strike~~** and ||spoiler with ==marked==||
### Links:

[Open a website](https://github.com/alireza-arm/AI_API_Learning/blob/main/telegram_bot.py)

[Open a Telegram channel](https://t.me/mechanical_engineering_ai)

[Open a Bale channel](https://ble.ir/your_channel)

[Send an email](mailto:amaleky36@gmail.com)

[Call a number](tel:+989021238463)

### Tap to copy

Tap this to copy: `F = ma`
### Expandable block

<blockquote expandable>This is a long quotation. Engineers often need to read several lines of explanation about a topic, but showing everything at once makes the post too long. With an expandable block, the long text stays collapsed until the reader taps it, and then the rest of the lines appear. Add as many sentences here as you need.</blockquote>

> [Mechanical_Engineering_AI](https://t.me/mechanical_engineering_ai)
"""

HTML = r"""<h2>Rich test (html)</h2>
<table bordered striped>
<tr><th>Quantity</th><th>Symbol</th><th>Formula</th></tr>
<tr><td align="center">Stress</td><td align="center"><tg-math>\sigma</tg-math></td><td align="center"><tg-math>\frac{F}{A}</tg-math></td></tr>
<tr><td align="center">Strain</td><td align="center"><tg-math>\varepsilon</tg-math></td><td align="center"><tg-math>\frac{\Delta L}{L_0}</tg-math></td></tr>
</table>
<p>Hooke's law inline: <tg-math>\sigma = E\varepsilon</tg-math></p>
<tg-math-block>\sigma_{max} = \frac{M c}{I}</tg-math-block>
<h3>Numbered list</h3>
<ol>
<li>Draw the free-body diagram</li>
<li>Write the equilibrium equations</li>
<li>Solve for the unknowns</li>
</ol>
<h3>Bullet list</h3>
<ul>
<li>Tension</li>
<li>Compression</li>
<li>Shear</li>
</ul>
<h3>Nested list</h3>
<ol>
<li>Loads
<ul>
<li>Static</li>
<li>Dynamic</li>
</ul>
</li>
<li>Supports
<ul>
<li>Fixed</li>
<li>Pinned</li>
</ul>
</li>
</ol>
<h1>Heading 1</h1>
<h2>Heading 2</h2>
<h3>Heading 3</h3>
<h4>Heading 4</h4>
<h5>Heading 5</h5>
<h6>Heading 6</h6>
<blockquote>Single-line block</blockquote>
<blockquote><p>First line of a multi-line block</p><p>Second line of a multi-line block</p></blockquote>
<details>
<summary>More info (tap to expand)</summary>
<p>Extra explanation with <b>bold</b> text and a formula <tg-math>\sigma = E\varepsilon</tg-math>.</p>
</details>
<pre><code class="language-python">print("copy me")</code></pre>
<h3>Text formatting</h3>
<p><b>Bold text</b></p>
<p><i>Italic text</i></p>
<p><u>Underlined text</u></p>
<p><s>Strikethrough text</s></p>
<p><tg-spoiler>Spoiler text</tg-spoiler></p>
<p><mark>Marked text</mark></p>
<p>Subscript: H<sub>2</sub>O</p>
<p>Superscript: x<sup>2</sup></p>
<p><b>bold <i>italic</i> <s>strike</s></b> and <tg-spoiler>spoiler with <mark>marked</mark></tg-spoiler></p>
<h3>Links:</h3>
<p><a href="https://github.com/alireza-arm/AI_API_Learning/blob/main/telegram_bot.py">Open a website</a></p>
<p><a href="https://t.me/mechanical_engineering_ai">Open a Telegram channel</a></p>
<p><a href="https://ble.ir/your_channel">Open a Bale channel</a></p>
<p><a href="mailto:amaleky36@gmail.com">Send an email</a></p>
<p><a href="tel:+989021238463">Call a number</a></p>
<h3>Tap to copy</h3>
<p>Tap this to copy: <code>F = ma</code></p>
<h3>Expandable block</h3>
<blockquote expandable>This is a long quotation. Engineers often need to read several lines of explanation about a topic, but showing everything at once makes the post too long. With an expandable block, the long text stays collapsed until the reader taps it, and then the rest of the lines appear. Add as many sentences here as you need.</blockquote>
<hr/>
<blockquote><a href="https://t.me/mechanical_engineering_ai">mechanical_engineering_ai</a></blockquote>
"""


def main():
    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    proxy = os.getenv("TELEGRAM_PROXY", "").strip() or None
    if "--channel" in sys.argv:
        target = os.getenv("TELEGRAM_CHANNEL_ID", "").strip()
    else:
        target = int(os.getenv("TELEGRAM_ALLOWED_USER_ID", "0"))
    api = TelegramAPI(token, proxy)
    for name, kwargs in (("markdown", {"markdown": MD}), ("html", {"html": HTML})):
        try:
            api.send_rich_message(target, **kwargs)
            print(f"{name}: sent OK")
        except TelegramError as exc:
            print(f"{name}: FAILED -> {exc}")


if __name__ == "__main__":
    main()