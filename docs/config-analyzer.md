# Configuration history and browser

[Documentation](README.md) · [Project README](../README.md)

## Configuration changes (`cn diff`)

```bash
cn diff r1 --since 24h
cn diff r1 --line 'ip route 0.0.0.0' --since 7d
```

`cn diff` lists the configuration lines added or removed on each device, each attributed to the
snapshot, author and time that made it. Snapshots are the current `<device>.cfg` and the files in
`history/<device>/`. It reads the directories of `[config_analyzer] repo_directories` when it is
set, else `[config_repo] directory`, and is unavailable when none of them is accessible or
`[config_repo] enabled` is `false`.

- Without `--since` the comparison starts at the previous snapshot (the last change); with `--line`
  and no `--since`, at the oldest. `--since` takes `30m`, `24h`, `7d`, `2w`, `2026-10-01`,
  `2026-10-01T14:00` (**UTC** unless `Z` or an offset is given) or a snapshot file name ending in
  `.cfg`; it starts at the newest snapshot at or before that time. The comparison ends at the
  newest snapshot.
- A line is identified by its text and its parent (the nearest line without indentation). Lines
  are counted, so a repeated line counts as often as it occurs; a pure reorder is not a change;
  blank lines and lines that are only `!` are ignored.
- A row is attributed to the last snapshot in the window that added or removed the line. A line
  added and removed again inside the window is not shown.
- `--line TEXT` keeps the lines that contain TEXT, in any case.

## Config Analyzer

The repository browser TUI (`config_analyzer` 0.2.0, Textual 8.2 or newer) can be launched either
from the menu or directly. One app hosts two screens: the repository browser (folders, devices
and a preview) and, on top of it, the snapshots of the device you opened. Select one snapshot to
read it, two to see their diff; Esc goes back to the browser exactly as you left it (folder,
cursor, filter and scroll position).

```bash
python -m config_analyzer --repo-path /path/to/repoA --repo-path /path/to/repoB
python -m config_analyzer --repo-path /path/to/repo --device r1   # open the snapshots of r1
```

An unknown `--device` is an error notification and the browser opens; a device without
snapshots is a warning notification.

| Key | Does |
| --- | ---- |
| `?` | Help panel with the keys that apply now. |
| `/` | Focus the filter line. Typing any other key on a list goes into the filter too, except `z`, `/` and `?` (a filter that starts with one of them needs `/` first). |
| Enter | Open a folder or device; in the snapshot list, select a snapshot (two show the diff). In the filter line it acts on the highlighted row and returns to the list. |
| Tab, Shift+Tab | Switch between the list and the document or preview. |
| `d`, `h` | Snapshots, document focused: unified or side-by-side diff; hide unchanged lines. |
| Ctrl+F, Alt+F | Find in the shown document: type, Enter or Down for the next match, Up for the previous one, Esc closes. |
| `z` | Maximise the document, while one is shown; again to restore. |
| Ctrl+L | Cycle the layout (right, bottom, left, top) without losing focus, scroll position or selection. |
| Esc | Close find, then restore a maximised pane, then clear the filter; in the snapshots then hide the document, then go back to the browser. |
| Ctrl+Q | Quit at once. |

`cn diff` reads the same snapshots without the TUI. `cn diff` and the TUI use
`[config_analyzer] repo_directories` when set, else `[config_repo] directory`.

Optional configuration:

```ini
[config_analyzer]
repo_directories = /path/to/repoA,/path/to/repoB
repo_names = repoA,repoB
layout = right
scroll_to_end = false
debug = false
```
