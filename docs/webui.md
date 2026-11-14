# Local browser interface

[Documentation](README.md) · [Project README](../README.md)

The optional WebUI runs on your computer and shares cn-tool's configuration, lookup
logic, enrichment and accumulating Excel workbook. It binds only to `127.0.0.1` and
serves its assets locally. It is intended for a local desktop session.

Infoblox lookups in the browser require the same WAPI-enabled account as the
command line. Grid Manager GUI access is not required. Check the [Infoblox access
and setup](infoblox.md#access-and-setup) requirements before using them.

## Version scope

| Version | Available browser tools |
| --- | --- |
| Released 0.8.4 | Subnets |
| 0.9.0 | Subnets, IP, Ping, Monitor, Configuration Search and Site Demobilization |
| 0.9.1 | The same tools, with live Monitor progress and history management |
| 0.9.2 | The same tools, with compact results and improved navigation |
| 0.9.3 | Column sorting and field filters, with Ping and Monitor outcome summaries |
| 0.10.0 | Monitor host page-size selection, Show Available lists on Subnets and Monitor, and a Windows Pydantic compatibility pin |
| 0.11.0 | Report deletion on every tool |
| 0.12.0 | Settings (edit the configuration and use it without a relaunch), and All rows, CSV download and copy for the Ping and Monitor tables |
| 0.12.1 | The same tools; on Windows, a start through signed Python and a shortcut without a console window, and one session per user |
| 0.12.2 | The same tools; **Ping these** and **Monitor these** on the IP and Subnets result tables |

The browser tools beyond Subnets are available in 0.9.0 and are not part of 0.8.4.
The menu and CLI have their own established workflows.

## Sorting and filtering results in 0.9.3

Select a column heading to sort and select it again to reverse the order. Use the
field filter to match text without regard to case; clear the filter to restore the
rows. Sorting and filtering apply across all result pages without changing reports.
Ping and Monitor offer outcome counts to narrow host results. Filtering a Site
Demobilization preview changes only the display; the configuration scan still uses
all eligible discovered networks.

## Installation and launch

```console
pipx install "cn-tool[webui]"
cn-web
```

For an existing pipx installation, use `pipx upgrade "cn-tool[webui]"`.
In a virtual environment you manage, use `python -m pip install "cn-tool[webui]"`.
To try upcoming features from a source checkout containing them, install that source
with `python -m pip install ".[webui]"`; check its revision and this guide's scope.

`cn-web -c FILE` adds a configuration file using the normal
[configuration precedence](configuration.md). `cn-web --port 8123` selects a predictable
local port; otherwise the launcher chooses an available one. If the executable is
not on PATH, use `python -m cn_tool.webui` with the same options in the Python
environment where cn-tool is installed. A system Python does not automatically see
a pipx environment's packages.

From 0.12.1, on Windows, `py -m cn_tool.webui --create-shortcut` writes a **cn-tool Web** shortcut to
the Start menu and the Desktop; `-c FILE` makes it open that configuration. The shortcut
starts the interface through the signed Python interpreter (`pythonw.exe`) without a
console window, so stop it with **Quit application**; `--console` writes one that keeps a
console window, where Ctrl+C also stops it. Run the command again after upgrading or moving
Python. On a managed PC, where application control blocks the unsigned `cn-web.exe` that pip
writes, see [Starting on a managed Windows PC](windows.md#starting-on-a-managed-windows-pc).

Keep the launcher running. A one-use launch link attaches the browser. From 0.12.1 there is one
session per user: starting `cn-web` (or its shortcut) again while it runs reopens the
browser on that session with a new link, and a different `-c FILE` is refused until the
running session is quit. Tabs share one
runtime, account and active operation. Closing or refreshing a tab leaves the application
running; use **Quit application** to finish the session. **Settings** edits the
configuration file and can apply it without a relaunch; see [Settings](#settings).

## Released interface (0.8.4)

Configure `[api] endpoint` and the existing credential sources before using Subnets;
`cn init` creates a starting configuration if needed. Missing configuration shows setup
guidance. Missing credentials open a masked dialog. Cancel returns to setup; **Retry
setup** attempts it again. Environment and GPG values retain precedence.

Paste IPv4/IPv6 addresses or subnets, one per line, and select **Look up**. The configured
network view applies, or every view when none is selected. Inputs and resolved networks
are deduplicated per applicable view. One network opens details directly; several open
a summary. **View details**, **Back to summary** and **Show all details** reuse fetched
data. **New lookup** leaves targets ready to edit. Refresh restores completed results
and clears an unsent Targets draft.

When native storage is available, **Remember credentials on this computer** starts
unchecked. After startup succeeds, a manually entered password can be saved in the
current OS user's secure store for this server and account. **Forget saved credentials**
removes that saved login while the current session stays signed in. After a saved login
fails, select Forget, then Quit and relaunch to enter a different login.

Windows Credential Manager, macOS Keychain and Linux Secret Service are supported in a
local desktop session. Headless Linux and a locked or unavailable store fall back to
manual entry. Store operations time out after 15 seconds. A timed-out or canceled save
or delete may already have reached the OS store, so its outcome is unknown. Passwords
are not stored in the browser; environment and GPG sources take precedence.

## Interface in 0.9.0

This section describes changes since 0.8.4. Missing configuration is explained
when a lookup needs it. Subnets and IP require Infoblox; Ping and Monitor do not.

A missing credential opens a masked dialog for that lookup. Cancel stops it and leaves
the application ready for another. Remember saves manually entered credentials after a
successful lookup. If a saved login is refused, Forget removes it; run the lookup again
to enter another login. The secure-store rules described above still apply.

Each tab retains separate unsent drafts for Subnets, IP, Ping and Monitor across refresh,
including Ping ports. A new independent tab starts with empty drafts.

### Subnets and IP

Subnets keeps the summary and detail workflow described above. Both lookup tools follow
the configured network-view scope and existing IPv4/IPv6 validation and enrichment.
Subnets summaries keep network, status, view and **Details** together in a paged table;
returning from details restores the summary position. **View results** jumps past setup.

From 0.10.0, a **Show Available** checkbox beside **New lookup** lists the addresses that have no record of
any type in Infoblox. It is unticked on every page load and works on the result on screen, so ticking it sends no
request. Each subnet's details gain **Unused addresses (N)**: a table of `network view` (where the other tables show
one, and first, as they do) and `IP address` (there is no status column, because every row would say the same) with the
usual text filter and paging. A line above the results gives the total (`Unused addresses: 344 in 2 networks`), says that
Unused means no record of any type in Infoblox and does not prove that nothing answers there, and names every input that
could not be listed, with its reason: not a network in Infoblox, records that could not all be read (a stopped lookup
included), network views that could not be listed, a container, an IPv6 subnet, or a network over 65,536 addresses.
**Download available IPs** saves a CSV of every listed subnet, with the columns of `cn subnet --available`, and a
`warnings` section with a row for each input that could not be listed, as `cn subnet --available --format csv` writes
them, so a short file cannot pass for a complete one; it is separate from **Download accumulated report** and does not
change it, and it is disabled while there are no rows. Unused means no record in Infoblox, not that nothing answers on
the address: see [Unused addresses](infoblox.md#unused-addresses-show-available).

IP accepts individual IPv4/IPv6 addresses, one per line. Results show address, network
status, network view and available data and plugin columns in a compact paged table.
Narrow screens scroll within the table to reach remaining fields. Invalid inputs, misses, request failures, PTR warnings
and unchecked work are shown separately. The latest attempt remains visible if it
produces no rows, alongside labelled previous useful results. Switching tools or
refreshing does not run a lookup again.

### Ping these and Monitor these

From 0.12.2, the IP results table, the Subnets summary and every Subnets detail table that lists
addresses (in use, fixed, DNS records, **Unused addresses**) have **Ping these (N)** and **Monitor these (N)** above
them. N is the number of targets in the table as it is filtered, on every page: apply the field filter first to send
fewer.
The targets are the rows' addresses, each once, in the table's order; the Subnets summary sends its subnets, one
per line, which Ping and Monitor test host by host as they do for a typed subnet. A row without an address or
subnet is left out and the button says how many; when the filter leaves no row the buttons are not shown, and
when no row holds an address they are disabled.

Selecting a button opens Ping or Monitor in the same tab with the targets in **Targets**. Nothing is started:
review the list, add TCP ports or an interval, and select **Run Ping** or **Run monitor**. The list is never
shortened. You are asked to confirm first when the tab already holds different unsent text in that Targets box
(it is replaced), when the targets cover more than 1,024 addresses (the most that TCP ports can be tested for),
or when a subnet is larger than a /16, which Ping and Monitor refuse.

### Ping

Paste IP addresses, hostnames or subnets, one per line, and optionally enter up to five
comma-separated TCP ports. Hostnames use system DNS with IPv4 preferred over IPv6.
ICMP uses the system `ping`; if it is unavailable, a TCP selection still runs and marks
ICMP as not run. The [ping limits](ping-monitor.md#bulk-ping-cn-ping) also apply here.

Invalid targets and DNS failures are separate from completed rows. Results show 50 rows a
page by default; **Rows per page** offers 5 to 100 and, from 0.12.0, **All (up to 1,024)**. Diagnostic
lists use pages of up to 50 items. Both have controls and page-number entry to reach every
item. Stop waits for DNS and active probes to drain and distinguishes incomplete from
unattempted hosts. Earlier useful results remain available when a new attempt yields none.

Ping results use one compact table on desktop and narrow screens, with the target,
ICMP result and TCP results grouped together. Scroll inside the table for additional
columns, or use **View results** to jump past setup. The target input scrolls when a
large list is pasted. Diagnostic sections show their counts and can be expanded; they
open automatically when the latest attempt has no completed results. Expanding or
paging diagnostics preserves the other sections' state.

### Monitor

Monitor repeatedly probes the same kinds of targets. Interval defaults to 60 seconds;
leave duration blank to continue until stopped. Both supplied values must be at least
10 seconds, and duration must be at least the interval.

The latest complete round uses bounded pages. This run's and earlier round counts are
shown separately; an incomplete first round is not an outage. History is a changing view
of recorded requests, runs, rounds and hosts, and refreshing it starts at page one.

From 0.10.0, latest-round and saved-round host tables have a bottom
pagination bar. Choose **Rows per page** and use the arrows to browse the matching
hosts. Changing the page size returns to the first page and preserves the chosen
sort and filters. Pages start at 25 rows; the choices run from 5 to 100 and, from 0.12.0,
**All (up to 1,024)**: every row of a table of 1,024 or fewer, pages of 1,024 beyond.

### Download table (CSV) and Copy table

From 0.12.0, the Ping results table and the Monitor latest-round, saved-round and Show Available host
tables have **Download table (CSV)** and **Copy table** above them. Both take the whole
table as it is filtered and sorted, every page, with the columns and headings on screen
(Ping has one column per TCP port; Monitor one TCP column).

- **Download table (CSV)** saves a comma-separated file that Excel opens with a
  double-click (UTF-8 with a byte-order mark, so `—` and `09:00–09:41` read correctly).
  Its name says which table and when, for example `cn-ping-20261112-090507.csv` or
  `cn-monitor-round-42-…`.
- **Copy table** puts the same rows on the clipboard as tab-separated text, so that they
  paste into separate cells of an existing sheet. If the browser does not allow the copy
  (for example because another window had the focus), return to the tab and select
  **Copy table** again.
- A cell that starts like a formula (`=`, `+`, `-`, `@`) and is not a number gets a
  leading `'`, so a host name never runs as a formula.
- For a Ping run that was stopped or is still running, the export includes the completed
  results and says so.
- On Monitor, a large table is read page by page: progress is shown, **Cancel** stops it,
  and the table's paging, sorting and filters wait until it finishes. A new live round
  arriving meanwhile stops it with a message; download again. **Download available IPs**
  stays as it was: every Unseen IP, whatever the filter.

Use the **Live monitor** tab for setup and current results, or **History** to browse saved
targets and runs in compact tables. **View rounds** opens a round selector alongside the
selected round's target/status table. **Earlier round** and **Later round** move through
rounds without returning to the run list, including across round pages. Host pages have
separate controls. On narrow screens, choose a round from **Round (UTC)**; targets and
statuses stay in adjacent columns. Rounds are ordered oldest first, and all timestamps
are UTC. **Back to runs** returns to the same run-list page.

It uses `[ping] history_file` and `[ping] history_days` (180 days by default from 0.10.0); viewing history
never prunes it.
Starting with 0.9.1, the live view shows progress during a round. Under a request's runs, **Use settings** loads the saved targets and TCP ports into the
form on the Live monitor tab without starting a monitor. Review the interval and duration before starting: a
finite duration is estimated from the saved schedule, and some older schedules need a
new interval. Very large saved requests may need to be entered manually. **Delete run**
removes one saved run; **Delete all history** clears all requests and runs. Each action
asks for confirmation. A recorded active run cannot be deleted, and it blocks clearing
all history.

Closing a tab or navigating away leaves this session's monitor running. **Stop monitor**
ends its own run; Quit stops it and waits for cleanup. History and workbook failures are
reported separately. Completed rounds from a stopped monitor can be included in the workbook.
See [monitor history](ping-monitor.md#ping-monitor-cn-monitor) for storage and retention details.

From 0.10.0, a saved target on the **History** tab has a **Show Available** checkbox, unticked whenever you
open a target. Nothing extra is read until you tick it. The page then reads the target line's whole history in the
background and stays usable, under the heading **Available IPs (whole history)**, which says what Unseen and Not tested
mean. It shows the rounds the list rests on (`2,880 rounds since 2026-07-09`), one notice listing each subnet in which no
IP ever replied (this machine may not reach it) and a table of every IP with its status (**Seen**, **Unseen** or **Not
tested**), first and last seen, rounds answered (`0 of 2,880`), failed rounds and a note. The **All**, **Seen**,
**Unseen** and **Not tested** buttons (with counts for the whole history) and the field filter narrow the rows, the
headings sort, and the bottom footer chooses rows per page as in the other host tables. **Download available IPs** saves a
CSV of every Unseen row of the target line with its note, whatever page, sort or filter is showing, and says how many
rows that is (`344 Unseen IPs, whatever filter is showing.`); it is separate from **Download accumulated report**, and
disabled until the table has loaded and while no IP is Unseen. **Refresh history** reads the list again. The box stays
ticked when you go into a run's rounds (**View rounds**) and back to the same target's runs, and the table is read again
then; another target, or the list of targets, starts with it unticked. The Live monitor tab does not change. Unseen means no reply to this machine in
the rounds kept, so a firewalled or sleeping host looks the same, and `history_days` must cover the period being
judged: see [Never-seen IPs](ping-monitor.md#never-seen-ips-show-available).

## Configuration tools in 0.9.0

These workflows are available in 0.9.0 and are not part of 0.8.4.
Configuration Search does not require Infoblox; Site Demobilization does. Configuration
Search and the Site Demobilization configuration scan currently run on Linux and Windows
only. On macOS, the Site Demobilization network lookup and the other WebUI tools remain
available. Both configuration searches need a configured local repository. Their inputs
and results are not saved in browser storage or URLs; the Site Demobilization confirmation
token stays session-owned.

### Configuration Search

Search the local repository configured in `[config_repo]`. Enter one IPv4 network,
address, site code or keyword per line. Keywords are regular expressions and need at
least five characters unless recognized as site codes. A site code searches configuration
text as a regular expression; it does not run a site demobilization check.

The WebUI supports live search. A repository explicitly disabled in `[config_repo]`
cannot be searched; enable it and relaunch. If no usable repository is configured,
check its directory and relaunch. A Site Demobilization network preview remains available
independently, but its configuration scan is refused until the repository is usable.
If a configured cache is active, the WebUI refuses the search and explains how to use
the menu or configure live search. If SD-WAN YAML search is enabled, Configuration
Search refuses the search; this integration is not supported in
the WebUI. Use the menu to include YAML results. Site Demobilization follows the menu's
core search and does not include YAML results. Inputs are limited to 200 lines, 1,024
characters per line and 64 KiB total. Search work is bounded to 10,000 entries and matches, 8 MiB of work and results, and 16 KiB per line. A limit, unreadable
file or detected source change makes the search incomplete. Narrow the search and retry.
Matches use pages of at most 50; line numbers start at zero. The compact match table
keeps device, line and configuration text together. On narrow screens the configuration
text spans the row below its device and line number. **Details** exposes the exact search
term and full file path. Page controls sit above the results, and **View matches** jumps
past setup. **Search help** explains syntax and limits. Diagnostic counts expand into
invalid-input and unmatched-network lists; they start open when there are no matches.

Source identity and containment are checked, and detected changes are rejected. The
search does not take an atomic filesystem snapshot or protect against another local
process deliberately swapping and restoring paths between checks. Stop waits for search
cleanup. Earlier completed results remain labelled when a later attempt is incomplete.

Search reports may include whole configurations. Treat their contents as sensitive.

### Site Demobilization

Enter a site code and select **Look up site networks**. The first stage authenticates to
Infoblox and shows the returned networks, views, utilization and notices. Review the
preview, then select **Search configurations** to search the configured live repository,
or **Decline** to end the check without scanning. Consent is available after a preview
page has loaded; the browser does not choose the networks or repository paths for the scan.

A check can search at most 200 distinct IPv4 networks. IPv6 and invalid network records
are skipped with notices. If discovery is incomplete, the warning remains visible during
the search and with the results; the check is partial and its report is not saved.
Preview and result pages show at most 50 rows; matching line numbers start at zero.
The preview uses aligned network/view columns, and result headings identify the site
and earlier results when available. Matched configuration rows keep device and line beside the text,
with search terms and full paths in **Details**. Page controls sit above the data.
Cached configuration mode is unavailable in this interface and is refused on confirmation.

The configured network view applies. If no view is configured, the search uses the
views available to the account; if the view list is denied, the preview warns that access
is limited and retains available view labels. Incomplete view discovery and a denied
configured view stop the preview. The preview remains available across navigation or
reload in the same live session for up to five minutes. Decline, a replacement lookup,
Stop, Quit or expiration invalidates it; confirmation can be used once. Automatic
reports and accumulated workbooks can contain full device configurations and earlier
results, so handle them as sensitive.

## Settings

From 0.12.0, **Settings** (in every page's tool links, and under **Setup required** on Subnets and IP)
creates and edits your configuration file without a text editor. It edits the file given with
`cn-web -c FILE`, otherwise `~/.cn` (`%USERPROFILE%\.cn` on Windows), and lists every file cn
reads, in order: a later file overrides an earlier one.

- The common settings come first (the same ones as the terminal **Application Setup**, menu
  `s`), followed by the settings this file already sets. **Show all settings** lists the rest,
  and **Find a setting** searches all of them. Each setting shows its help, its value if this
  file does not set it (inherited from an earlier file, or the default), and the template's
  example.
- **Remove** takes a setting out of the file, so the inherited value applies again. Emptying a
  box sets the setting to empty in this file; **Set empty** does the same for a setting the
  file does not have yet. An empty value overrides an earlier file; for example, an empty
  `[ssh] config_file` turns the SSH config off.
- **Create file** writes the commented `cn init` template when no earlier configuration file
  exists. Otherwise it writes only the settings you set, so that the earlier files stay in
  effect. **Save changes** rewrites only the lines that change, and keeps your comments and
  every setting the page does not show.
- Values are checked when you leave a box and when you save. Numbers must be whole, an
  endpoint must be an `http://` or `https://` URL, and `[auth]` entries must be variable
  names. Patterns must be valid regular expressions.
- If the file changed on disk after the page loaded it, nothing is saved. Reload, with or
  without your edits.
- Passwords are never shown or saved here, including the SMTP password in `[email]`. Keep them
  in the environment or a GPG file.
- After saving, **Use the new settings now** reads the configuration again in the running
  window, when no work is running (a login you typed in this window is asked for again; saved,
  environment and GPG credentials are found again). **Quit now** and starting `cn-web` again
  works too. `cn` commands use the new settings from their next run. In **Setup required**,
  **Retry setup** also reads the configuration again.

## Reports, Stop and Quit

**Delete report** (from 0.11.0) appears beside the
download button on every tool. Its confirmation names the report file (the file name only)
and says that it removes the whole accumulated report shared by all the tools,
including the sheets of the other tools. Results on screen, Monitor history and the
copies already prepared or downloaded stay. So do the **Download available IPs**
lists, which come from Infoblox results and the Ping history, never from the
workbook. The next saved results create a new report.

Deletion is offered only while nothing is running, no report write is pending and no
report download is being prepared. The application checks again when you confirm and
refuses if work has started in another tab meanwhile. While it runs, every open tab
shows its progress, operation starts and report downloads are disabled in all of
them, and **Quit** stays available. Each tab then announces **Accumulated report
deleted.** or **No accumulated report exists.**, and no tool shows an older
**Report saved** label again until a later operation saves; that save enables
download and delete again.

The workbook is removed only after the application has taken the report's locks. If
another program holds it (Excel keeps a workbook open on Windows) or another process
holds its lock, the report stays, the message tells you to close it and try again, and
you can retry at once. If the session ends before the application confirms the
deletion, the page says so.

Automatic reporting follows `[report] auto_save`. Completed reportable lookups append
once to the configured accumulating workbook. Navigation does not save again, and
stopped one-shot or unreportable lookups add no report. Save failures leave results
available. Version 0.9.0 shows the effective report directory and warns if an
inaccessible configured directory causes startup to fall back to another directory.

**Download accumulated report** waits for pending writes and downloads a consistent copy of the
existing workbook. It does not enable reporting or save a selected view. After a failed
or disabled save, the downloaded file may contain only earlier results. The accumulated
workbook may hold earlier sensitive information as well as the current result.

**Stop** cooperatively prevents new work after in-flight requests finish within configured
timeouts. It is disabled during saving. In 0.9.0, Subnets and IP can retain
completed fetch-stage data. Their resolution is collected per input, so stopping during
multi-view resolution can omit an input even if one view has answered. Existing completed
results and reports remain available. A stopped
configuration search or Site Demobilization check does not publish unfinished matches
or save a report.

**Quit application** runs configured exit actions once (including email and
delete-after-send when enabled), then closes the worker and server. In 0.9.0,
Quit stops Monitor and waits for cleanup and any report save already in progress; other
active work drains. Quit also stops active configuration searches, including Site
Demobilization.
Closing a tab does not run exit actions. An unexpected worker failure is displayed
without rerunning work or replaying email. Ctrl+C also stops a local WebUI session
cleanly on Windows (from 0.8.4; 0.9.0 to 0.11.0 also printed a traceback from a
background process as they ended, which 0.11.1 removes); interruption skips normal
exit actions inappropriate for a canceled session.
