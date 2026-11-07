# Release highlights and upgrade notes

[Documentation](README.md) · [Project README](../README.md)

## Documentation at release time

Before publishing a new version, review the README's **Browser interface**
paragraph, this guide's release list, the documentation index's version scope and
the WebUI guide's version table and current-source sections. Mark only the
features included in that release as released; keep the 0.8.4 behavior available
as historical guidance. Review credential, draft and report behavior as well as
the list of tools. An implementation merge alone does not change package availability.

README links to `main` intentionally follow current source. A release-specific
reference must use a tag containing those documents. Do not point the new guides
at an older tag that contains only the original README. Validate local staged
files and fragments before publishing, and check their public URLs after publication.

## 0.11.0

Every web tool offers **Delete report** beside the download button. After a
confirmation that names the report file, it deletes the whole accumulated report that
all the tools share, including the sheets of the other tools; results on screen,
Monitor history and copies already prepared or downloaded stay, and the next saved
results start a fresh report. Deletion is offered only while nothing else is running
or saving, and it never removes the workbook when it cannot take the report's locks:
a workbook that is open in Excel or another program stays, and the message says to
close it and try again. **Show Available** downloads do not read the workbook and are
not affected. See the [WebUI guide](webui.md#reports-stop-and-quit).

The menu's **Delete report** follows the same rule: when another process holds the
report's lock for more than ten seconds, it now keeps the file and prints the error,
where it used to delete the file anyway. It also waits for saves that are still
queued before it takes the lock, which it did not do before.

`cn monitor --format csv` now writes the `Online` column with a plain hyphen
(`09:00-09:41`), so Excel shows it as written; the table, Markdown, JSON and the
workbook keep the en dash. A script that matches the en dash in CSV output needs updating.

When `cn-web` cannot start, its message reaches stderr once, and it no longer hangs
when stderr is redirected. The error box at a desktop closes itself after 60 seconds;
on macOS no box appears when stderr exists. Closing a page while a download is being
prepared no longer leaves the prepared file behind until Quit. Monitor's rows-per-page
menus open and close without animation, so they no longer take focus back when
reopened quickly. `cn monitor --show ID --available` exits 3 and says so when the run
is deleted while it is being read.

## 0.10.0

Monitor's latest-round and saved-round host tables use a bottom pagination bar
with a rows-per-page selector and arrow navigation. The Windows WebUI extra pins
Pydantic to 2.14.2, whose matching pydantic-core 2.50.2 worked on a workstation
where application control blocked the newer 2.50.4 binary. Local policy still
determines which binaries may run.

**Show Available** lists IPs that nothing seems to use, in the browser (a checkbox on
Subnets and on Monitor's History tab) and on the command line (`--available` on
`cn subnet` and `cn monitor`). On Subnets it lists the IPv4 addresses with no record of
any type in Infoblox, from the lookup already made; a subnet that cannot be listed with
certainty is named with its reason and, on the command line, ends the run with status 3.
On Monitor it lists the IPs of a target line that never replied in any round kept. Each
web table has a **Download available IPs** button that saves a CSV. Neither list proves
an address is free: check it before you reuse the address or delete its record. See
[Unused addresses](infoblox.md#unused-addresses-show-available) and
[Never-seen IPs](ping-monitor.md#never-seen-ips-show-available).

The default of `[ping] history_days` is now **180** days instead of 30, so a long watch
keeps the evidence an Unseen list needs. A configuration that sets a value keeps it. The
history file can grow to as much as six times its old size, and rounds already deleted
do not come back; see [Configuration](configuration.md).

## 0.9.3

Result tables support column sorting and case-insensitive field filtering across
all pages. Ping and Monitor offer compact outcome summaries. Filtering a Site
Demobilization preview does not change the networks included in its scan. See the
[WebUI guide](webui.md).

## 0.9.2

The browser interface uses compact, paged results for Monitor, Ping, IP,
Subnets, Configuration Search and Site Demobilization. Monitor separates live
and history views and adds a round inspector. An interrupted browser asset
request no longer triggers a `No response returned` error. See the
[WebUI guide](webui.md).

## 0.9.1

Monitor shows live round progress and clearer run history in the browser. Use a
past run's targets and TCP ports to fill the form, delete an individual run, or
clear history. The CLI adds `cn monitor --runs REQUEST_ID` and
`cn monitor --delete-run RUN_ID`. The SQLite schema remains compatible with
cn-mon. See the [Monitor guide](ping-monitor.md#ping-monitor-cn-monitor) and
[WebUI guide](webui.md).

## 0.9.0

Version 0.9.0 adds IP, Ping, Monitor, Configuration Search and Site Demobilization
to the local WebUI alongside Subnets. These additions are not part of 0.8.4.
Configuration scans currently require Linux or Windows; macOS can still show the Site
Demobilization network preview. Windows-native verification remains deferred. Review the
[WebUI guide](webui.md#version-scope) for consent, cache, YAML integration and report limits.

## Recent releases

- [0.8.4](https://github.com/evdanil/cn-tool/releases/tag/v0.8.4): `python -m cn_tool.webui`
  launch support and clean Windows Ctrl+C shutdown of the local WebUI.
- [0.8.3](https://github.com/evdanil/cn-tool/releases/tag/v0.8.3): optional local Subnets UI,
  native credential storage, explicit Quit and configurable loopback port.
- [0.8.2](https://github.com/evdanil/cn-tool/releases/tag/v0.8.2): package-description and
  documentation fixes describing changes already present in 0.8.1.

The [Releases page](https://github.com/evdanil/cn-tool/releases) holds the full tagged
release notes and downloadable artifacts. See the
[WebUI version table](webui.md#version-scope) for browser tool availability.

## What's new in 0.8.1

The Ping Monitor can now delete from its history and run a recorded request again. `cn monitor
--delete ID` removes one recorded request with its runs and rounds, and `cn monitor --clear` removes
every one; both ask first (`[y/N]`; without a terminal they need `-y/--yes`), refuse while a run of
the request goes on, and `--clear` gives the space back to the file system. `cn monitor --rerun ID`
starts a new run of a recorded request with its stored targets and TCP ports and the interval and
length of its newest run that had an interval; `--every` and `--for` change them, and a request with
a run going on is refused. In the menu (`m`), a request's summary has `r` (run it again) and `d`
(delete it), and the list has `c` (clear the history). The live table that `v` shows now has a `Flag`
column, one `TCP <port>` column for each `--tcp` port, and `Latest ping` in place of `Latest`: `OK` is
the ICMP result alone, whatever the ports did. Typing objects at a terminal (`cn ip -`) now says on
stderr how to end the input (Ctrl-Z, then Enter, on Windows), and Ctrl-C there prints `cn:
interrupted` and exits 130 instead of a Python traceback. No command, configuration key or
dependency is added, and the history's format is unchanged. See
[Ping monitor](ping-monitor.md#ping-monitor-cn-monitor), [Command line](cli.md#command-line) and the release notes
of 0.8.1 on the [Releases page](https://github.com/evdanil/cn-tool/releases).

## What's new in 0.8.0

The Ping Monitor, menu item `m` and the command `cn monitor`, pings a set of targets round after
round for as long as you choose and records every round in a history file
(`~/.cn-ping-history.db`; SQLite from Python's standard library, so no new dependency). Its summary
says which hosts were seen, when first and last, and when they stayed online; running the same
targets again adds the earlier rounds. While a run goes on, a small network is drawn as a live grid,
one character per address. The recorded requests, running ones included, can be listed, shown and
followed from another terminal without pinging (`cn monitor --list`, `--show ID`, `--follow ID`).
Two configuration keys are new, `[ping] history_file` and `[ping] history_days`. `cn ping` and Bulk
PING (item 6) are unchanged, except that on macOS an IPv6 ping to an address without a route now
reads `NO ROUTE`, as on Linux. See [Ping monitor](ping-monitor.md#ping-monitor-cn-monitor) and the release notes
of 0.8.0 on the [Releases page](https://github.com/evdanil/cn-tool/releases).

## What's new in 0.7.0

cn-tool runs natively on Windows 10 and 11 and installs from PyPI: `pipx install cn-tool` puts the
commands `cn` and `cn-tool` on your PATH (`python -m cn_tool` works too). A new command, `cn init`,
writes a commented starting configuration to `~/.cn`, and `cn doctor`, the menu and a refused lookup
point to it while no configuration file exists. On Windows, Bulk PING uses the system's `ping`, the
device login's user name comes from `USERNAME`, Bulk Network Trace is not available (it needs
`mtr`), and the command line writes UTF-8. Bulk PING also works on macOS now. `.cn` is read as UTF-8
(a byte-order mark is fine). Nothing else changes for an install that has a configuration file. The
details, and what to do when you upgrade a zip or a clone, are in the release notes of 0.7.0 on the
[Releases page](https://github.com/evdanil/cn-tool/releases). Version 0.6.0 let Infoblox log in
with its own account, for example a read-only service account (`INFOBLOX_USER` or `[api] user`, and
`INFOBLOX_PW` or a GPG file in `[gpg] infoblox_credentials`; the variable names are configurable in
`[auth]`). Version 0.5.0 added IPv6 to the Infoblox lookups and the bulk tools and a faster start,
version 0.4.1 made a command load only the libraries it uses, version 0.4.0 added Infoblox network
views, and version 0.3.0 the command line, `cn diff`, `cn doctor` and Config Analyzer 0.2.0; their
notes are on the same page.
