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

## Unreleased

## 0.14.1

The browser tools get **Clear results** and text boxes you can resize. The command line and the menu are unchanged.

**Clear results.** On Subnets, IP, Ping, Configuration Search and Site Demobilization, **Clear results** among the
outcome's buttons removes the result from the page once nothing of it runs: the tables, the summary and the outcome line
go, the form opens with what you typed and takes the focus, and the page says "Results cleared." The report keeps what
was saved and nothing is stopped; a reload or Back finds the page cleared, and a new run shows its result as usual. If
another tab ran the tool since, nothing is cleared and the page says "Not cleared: the results changed." The Monitor
offers it once the run has stopped or has failed before its first round; its history files stay.

**Text boxes you can resize.** On a desktop, the Targets boxes (Subnets, IP, Ping and Monitor) and Configuration
Search's Search terms have a handle to drag them up to 70% of the window and down to three lines; a size you dragged is
kept while you type. Phones and windows under 600 pixels have no handle (Configuration Search's box had one at any width
before). The Monitor's Targets box used to grow without limit while typing; on a desktop it now stops at ten lines like
the others. See [Resizing the text boxes](webui.md#resizing-the-text-boxes) in the web interface guide.

No configuration change or migration is needed, and no dependency changed.

## 0.14.0

A Monitor can now run beside one other tool in the browser, every Targets box reads pasted lists the same way, and the
Monitor says what changed. The command line and the menu are unchanged, except for the new `[ping] parallel_probes`
setting.

**A Monitor runs beside one other tool in the browser.** Start a Subnets, IP or Ping lookup, a configuration search or a
Site Demobilization check while a Monitor runs, and the Monitor's rounds go on; each job stops, saves and ends alone.
Two lookups still do not run together, and a second Monitor does not start. The header shows both jobs, each with a
pill and, on a page that does not own the job, **Stop…**, which asks first. The banner on a page that cannot start a
lookup says "Other lookups wait until it finishes." (a Monitor makes nothing wait). A job that is only waiting to save
its report, because the other job is saving, can be stopped, and then it is not saved. **Delete report…** and **Use the
new settings now** wait until both jobs have ended and say which job is in the way. A Ping beside a Monitor is two
sweeps at once, so up to twice the `ping` processes and TCP probes of either alone; `[ping] parallel_probes` limits
each. See [Reports, Stop and Quit](webui.md#reports-stop-and-quit).

**Every Targets box reads what you paste the same way.** On Subnets, IP, Ping and Monitor, items may be separated by
lines, commas, semicolons or spaces; `10.20.40.0 255.255.255.192` is one network, `192.0.2.10-20` is a range (not on
Subnets), a URL or `host:port` gives its host, and `#` starts a comment. A line under the box says what it holds and
lists what was not understood. The box keeps your text, what is sent is one item per line, and the command line is
unchanged. A Targets box holds what it can send, about 900 KB (roughly 75,000 addresses, one per line): a paste or an edit that
would pass that is refused whole, the box keeps what it had, and a message under it says to split the list, use ranges or
CIDR, or use a file with the command line (before, a paste of about a megabyte was silently lost). **Ping these** and
**Monitor these** write a long run of consecutive addresses as one range, which reads the same, and say so when a list
cannot be written to fit.

**The Monitor lists what changed.** A closed **Changes** box beside the Map and Table buttons shows the hosts that started or
stopped answering in each complete round, newest first, with the time (UTC), the host and its address and the Map's
words for the old and new state; **Show on map** puts the Map's cursor on the host. The last 200 changes are kept, and a
gap is said, not guessed. While the tab is in the background its title counts the hosts that stopped answering
("(3↓) Monitor – cn-tool"). **Notify me about changes** is an opt-in desktop notification, one per changed round, with
counts and no host names, sent only while the page is not visible and focused. See
[Changes and notifications](webui.md#changes-and-notifications).

**Subnets: Show Available as a table.** On a lookup of several networks, **Show Available** shows the unused addresses of
all of them in a table on the page, above the summary (paged, with a filter), as well as the **Download available IPs**
button; before, the table was only inside each network's details.

**A new setting, `[ping] parallel_probes`,** sets how many hosts Ping and the Ping Monitor ping, and TCP-probe, at the same
time: in `cn ping`, `cn monitor`, the menu and the browser. It takes a whole number from 1 to 1024; the default is 100,
the number every earlier version used, so a configuration without it behaves as before. It is an upper bound: on Linux
and macOS every ping keeps a file open and every TCP probe another, and when the system's open-file limit is too low
even after cn has raised its own, fewer run at once and the run says so when it starts (on the command line; in the
browser only in the log file). A value outside 1 to 1024 is reported and 100 is used; `cn doctor` shows it as an error,
and the browser's **Settings** page does not save it. A Monitor run uses the value it started with. A ping that cannot
start because no file or process is left now reads `ERROR` for that host, and a TCP probe that gets no thread reads
`error`, instead of ending the run with an error. The default, 100, is never lowered. See
[Configuration](configuration.md).

**A restored Targets box no longer stays empty on a slow machine.** After **Ping these**, **Monitor these**, a reload or
a return to a tab, the box could be enabled but left empty when the browser's answer took more than five seconds, and
text typed then replaced the kept list. The page now writes the kept text as soon as it can.

No configuration change or migration is needed, and no dependency changed.

## 0.13.0

The web interface is reworked so that every tool reads the same way and the results are on the first screen. The command
line and the menu are unchanged.

- Every tool opens inside one browser page, without a load: the header and the running-job pill stay, and **Back** and
  **Forward** move between tools. After **Look up**, **Run Ping** or **Run monitor** the form folds into one line with
  **Run again** and **Edit**. See [Moving between pages](webui.md#moving-between-pages) and
  [After you run: the form folds](webui.md#after-you-run-the-form-folds).
- The address in the browser names the view (a network's details, how a table is filtered, sorted and paged, a Monitor
  round), a reload opens it again, and **Copy view link** copies it. It never holds targets, search terms or passwords.
- Every table has one **Filter** box over all columns (there is no field to choose, no **Apply filter** and no **Clear
  filter**) and one footer, and **Download table (CSV)** and **Copy table** are on every table. Ping tables start at 25
  rows per page. Configuration matches are grouped by device with the match highlighted and **Copy path**.
- A running Ping shows a progress bar and the hosts probed so far. The Monitor has a line giving the round, the next
  round's countdown and the run's settings in UTC, and its Map has **Previous block with answers** and **Next block with
  answers**.
- Keys: a skip link, `/`, `?`, `g` then a letter, and Ctrl+Enter; **Single-key shortcuts** in **Help** turns the single
  keys off. The pages follow the system's light or dark setting.
- A password that Infoblox refuses keeps the sign-in dialog open, for up to three passwords in one lookup, and the lookup
  then offers **Sign in again**. **Stop** is on the page of the tool that owns the job, **Quit** says what it will do
  before it does it, and the **Report** menu in the header downloads or deletes the accumulated workbook.
- A page with no session, an expired launch link and an unknown address each get one plain card, and a port that is in use
  is named.

No configuration change or migration is needed.

## 0.12.3

In the web interface, Monitor's latest complete round opens as a **Map**: the grid of `cn monitor`,
one character for each address (`!` replied, `R` rejected, `T` TCP only, `x` gone, `U` unreachable,
`E` error, `?` unresolved name, `.` silent; reverse video for a change in the last round). Point at
a character, tap it, or move to it with the arrow keys for the host's details; the times in them
are in UTC. **Table** above the Map switches to the paged table, and the tab remembers the choice.
The Map always shows the whole round: filters and sorting apply to the Table only. Up to 65,536
addresses are drawn; a larger run shows one counter line for each subnet, with **Show this block**.
See [Map and Table](webui.md#map-and-table).

- On Windows, the **cn-tool Web** shortcut has an icon. Run
  `py -m cn_tool.webui --create-shortcut` again to give it to a shortcut you already have.
- Every page of the web interface ends with the cn-tool version in use and the copyright holder,
  and `cn --version` prints the copyright holder on a second line. A script that reads the version
  should read the first line.
- pandas is pinned to 3.1.0 on Python 3.11 and later. On Python 3.10, which pandas 3 does not
  support, cn-tool keeps the pandas 2.x line (2.2.2 or later).
- **Download accumulated report** on the Subnets, IP, Ping and Monitor pages is off until the page
  has its first status, so a click made while the page is still settling is no longer lost.
  **New lookup** puts the cursor in **Targets** at once, and Settings puts it at once in the first
  setting to correct after a save that was refused.

No configuration change or migration is needed.

## 0.12.2

In the web interface, the IP results table, the Subnets summary and the Subnets detail tables that
list addresses (in use, fixed, DNS records, **Unused addresses**) have **Ping these (N)** and
**Monitor these (N)** above them. They open Ping or Monitor with the table's addresses, as it is
filtered, in **Targets**; nothing is started until you select **Run Ping** or **Run monitor**. The
Subnets summary sends its subnets, which Ping and Monitor test host by host. You are asked to
confirm before unsent text in Targets is replaced, for more than 1,024 addresses, and for a subnet
larger than a /16. See [Ping these and Monitor these](webui.md#ping-these-and-monitor-these).
No configuration change or migration is needed.

## 0.12.1

On Windows, `py -m cn_tool.webui` and `py -m cn_tool` start cn through the signed Python
interpreter instead of the unsigned `cn-web.exe` and `cn.exe` launchers that application
control may block; see [Starting on a managed Windows PC](windows.md#starting-on-a-managed-windows-pc).
`py -m cn_tool.webui --create-shortcut` writes a **cn-tool Web** shortcut to the Start menu and
the Desktop that opens the interface without a console window (`--console` keeps one), and
programs cn runs, such as `ping.exe`, no longer open console windows of their own. Starting the
web interface again while it runs reopens the browser on the running session instead of
starting a second one. A start without a console now works, and a failed one shows its error in
a **cn-tool Web** message box. No configuration change or migration is needed.

## 0.12.0

**Settings** creates and edits the configuration file (`-c FILE`, else `~/.cn`) in the
browser. Saving rewrites only the changed lines and keeps comments, refuses a file that
changed on disk since it was loaded, and never shows or saves a password.
**Use the new settings now** applies them without a relaunch when no work is running, and
**Retry setup** reads the configuration again. Ping and Monitor tables offer
**All (up to 1,024)** rows per page, **Download table (CSV)** (UTF-8 with a byte-order
mark, for Excel) and **Copy table** (tab-separated, for pasting into a sheet), over the
whole table as filtered and sorted. On the Monitor's History tab, **Show Available**
keeps the keyboard focus on its box while a page of its table is still being read.
No configuration change or migration is needed.

## 0.11.1

On Windows, Ctrl+C in the console window that runs `cn-web` ends the web interface
quietly again, with exit code 130. Since 0.9.0 it also printed a `KeyboardInterrupt`
traceback from the background process behind Configuration Search. A Ctrl+C while
credentials are read from or saved to the system's credential store no longer prints
a traceback either.

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
