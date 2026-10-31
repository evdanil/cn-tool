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

The browser tools beyond Subnets are available in 0.9.0 and are not part of 0.8.4.
The menu and CLI have their own established workflows.

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

An administrator can create a desktop shortcut to the installed `cn-web` executable.
On Windows it is typically `<venv>\Scripts\cn-web.exe`; for pipx, use `pipx environment`
to locate its executable directory. Quote paths containing spaces and optionally append
`-c "C:\path\chosen.cn"`. Shortcut creation is manual.

Keep the launcher running. A one-use launch link attaches the browser. Tabs share one
runtime, account and active operation. Closing or refreshing a tab leaves the application
running; use **Quit application** to finish the session. Configuration changes require
Quit and relaunch. The interface does not edit configuration.

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

IP accepts individual IPv4/IPv6 addresses, one per line. Results show address, network
view, status and available data and plugin columns; narrow screens expose remaining
values through **More fields**. Invalid inputs, misses, request failures, PTR warnings
and unchecked work are shown separately. The latest attempt remains visible if it
produces no rows, alongside labelled previous useful results. Switching tools or
refreshing does not run a lookup again.

### Ping

Paste IP addresses, hostnames or subnets, one per line, and optionally enter up to five
comma-separated TCP ports. Hostnames use system DNS with IPv4 preferred over IPv6.
ICMP uses the system `ping`; if it is unavailable, a TCP selection still runs and marks
ICMP as not run. The [ping limits](ping-monitor.md#bulk-ping-cn-ping) also apply here.

Invalid targets and DNS failures are separate from completed rows. Results and diagnostic
lists use pages of up to 50 items, with controls and page-number entry to reach every
item. Stop waits for DNS and active probes to drain and distinguishes incomplete from
unattempted hosts. Earlier useful results remain available when a new attempt yields none.

### Monitor

Monitor repeatedly probes the same kinds of targets. Interval defaults to 60 seconds;
leave duration blank to continue until stopped. Both supplied values must be at least
10 seconds, and duration must be at least the interval.

The latest complete round uses bounded pages. This run's and earlier round counts are
shown separately; an incomplete first round is not an outage. History is a changing view
of recorded requests, runs, rounds and hosts, and refreshing it starts at page one.
It uses `[ping] history_file` and `[ping] history_days`; viewing history never prunes it.
Other processes' runs are view-only.

Closing a tab or navigating away leaves this session's monitor running. **Stop monitor**
ends its own run; Quit stops it and waits for cleanup. History and workbook failures are
reported separately. Completed rounds from a stopped monitor can be included in the workbook.
See [monitor history](ping-monitor.md#ping-monitor-cn-monitor) for storage and retention details.

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
Matches use pages of at most 50; line numbers start at zero.

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
Cached configuration mode is unavailable in this interface and is refused on confirmation.

The configured network view applies. If no view is configured, the search uses the
views available to the account; if the view list is denied, the preview warns that access
is limited and retains available view labels. Incomplete view discovery and a denied
configured view stop the preview. The preview remains available across navigation or
reload in the same live session for up to five minutes. Decline, a replacement lookup,
Stop, Quit or expiration invalidates it; confirmation can be used once. Automatic
reports and accumulated workbooks can contain full device configurations and earlier
results, so handle them as sensitive.

## Reports, Stop and Quit

Automatic reporting follows `[report] auto_save`. Completed reportable lookups append
once to the configured accumulating workbook. Navigation does not save again, and
stopped one-shot or unreportable lookups add no report. Save failures leave results
available. Version 0.9.0 shows the effective report directory and warns if an
inaccessible configured directory causes startup to fall back to another directory.

**Download report** waits for pending writes and downloads a consistent copy of the
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
without rerunning work or replaying email. In 0.8.4, Ctrl+C also stops a local WebUI
session cleanly on Windows; interruption skips normal exit actions inappropriate for
a canceled session.
