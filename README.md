# BLHS Hide AI

Microsoft Edge extension that Bishop Luers High School IT deploys to student accounts to hide
AI-generated answers in Google and Bing search. It is force-installed by policy and has no settings.

| Site | Hidden | Redirected to normal search |
|---|---|---|
| Google | AI Overview, AI Mode tab and buttons, "People also ask", homepage "+" button | AI Mode (`udm=50`), `/ai`, `/aimode` |
| Bing | AI Overview, AI Mode tab, "Ask Copilot" bar, homepage Copilot button | `/copilotsearch` (Bing AI Mode), `/chat` |

It only runs on `www.google.*` and `www.bing.com`.

## Layout

- `src/`: extension source
- `tools/build_release.py`: checks, packs, signs and verifies a release
- `update.xml`, `BLHS-Hide-AI.crx`: the current release, served by GitHub Pages
- `CHANGELOG.md`: release history

## Credits

Google selectors are derived from [hide-google-ai](https://github.com/asahisuenaga/hide-google-ai)
by Asahi Suenaga (MIT). See `LICENSE`.
