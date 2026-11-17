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
| 0.12.3 | The same tools; the Monitor **Map** view of the latest round, an icon for the Windows shortcut, and the version on every page |
| 0.13.0 | The same tools in one browser page: results first with **Run again**, one table style with a quick filter, Ping progress, view links, single-key shortcuts, a dark theme that follows the system, a sign-in that stays open, and a clearer **Stop** and **Quit** |

The browser tools beyond Subnets are available in 0.9.0 and are not part of 0.8.4.
The menu and CLI have their own established workflows.

From 0.12.3, every page ends with one small line: the cn-tool version in use and the copyright holder.

## Sorting and filtering results in 0.9.3

Select a column heading to sort and select it again to reverse the order. Sorting and
filtering apply across all result pages without changing reports.

Every table of the web UI (Subnets, IP, Ping, Configuration Search, Site Demobilization and the
Monitor's host tables) of eight rows or more has one **Filter** box above it. It
matches text, without regard to case, in any column of the table and acts while you type:
there is no field to choose and no **Apply filter** or **Clear filter** button. Empty the
box, or press **Escape** in it, to see every row again. A line beside the box says how many
rows are left ("12 of 340 rows", or "No rows match this filter."). Under a table of more
than five rows are **Rows per page** (5 to 100, or **All (up to 1,024)**; 25 at first), the
rows shown ("26–50 of 340") and **First**, **Previous**, **Next** and **Last**. A column
that holds nothing in any row is left out, a long value is cut short and shown whole when
you point at it, a status is a small label, and on a screen of 600 px or wider the first
column (the network or the address) stays in view while the table scrolls sideways.

The Monitor's History lists (saved targets, runs, rounds) have the same box and the same
footer. Ping and the Monitor's host tables have buttons above the table that narrow it to
one outcome ("Answered (12)"); their counts follow the filter. Filtering a Site
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
local port; otherwise the launcher chooses an available one. When that port is in use the
launcher says so ("cn-tool Web could not listen on port 8123: it is in use. Try again in a minute or
start without --port."); on Linux and macOS a restart right after **Quit** works. If the executable is
not on PATH, use `python -m cn_tool.webui` with the same options in the Python
environment where cn-tool is installed. A system Python does not automatically see
a pipx environment's packages.

From 0.12.1, on Windows, `py -m cn_tool.webui --create-shortcut` writes a **cn-tool Web** shortcut to
the Start menu and the Desktop; `-c FILE` makes it open that configuration. From 0.12.3 the shortcut has
the cn-tool icon (run the command again for a shortcut written by an earlier version). It
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
`cn init` creates a starting configuration if needed. Without an API endpoint, Subnets, IP and
Site Demobilization show a card, **Connect cn-tool to Infoblox**, in place of their form; its
**Open Settings** button leads to [Settings](#settings). Ping and Monitor do not need
Infoblox and never show it. If the session cannot start (for example the configuration cannot be read), Subnets, IP,
Ping and Site Demobilization show **Setup required** with the reason, **Retry setup** and a
link to Settings (see [Settings](#settings)). Missing credentials open the sign-in dialog
(below). Environment and GPG values retain precedence.

Paste IPv4/IPv6 addresses or subnets, one per line, and select **Look up**. The configured
network view applies, or every view when none is selected. Inputs and resolved networks
are deduplicated per applicable view. One network opens details directly; several open
a summary. **View details**, **Back to summary** and **Show all details** reuse fetched
data. The result is headed by what it found (for example "9 networks found", or "3 addresses
found · 2 lines not understood" on IP): counts of zero are left out, a failed lookup is headed by
its reason, and lines the tool did not understand are listed under the heading (open when five
or fewer). While the page's own lookup runs, the results on screen are labelled "Results of the
earlier lookup". Refresh restores completed results and keeps an unsent Targets draft (see below).

When native storage is available, **Remember credentials on this computer** starts
unchecked. After startup succeeds, a manually entered password can be saved in the
current OS user's secure store for this server and account. **Forget saved credentials**
removes that saved login while the current session stays signed in. After a saved login
is refused, the outcome says "Infoblox did not accept the password for <name>." with
**Sign in again**; see [Signing in](#signing-in-to-infoblox).

Windows Credential Manager, macOS Keychain and Linux Secret Service are supported in a
local desktop session. Headless Linux and a locked or unavailable store fall back to
manual entry. Store operations time out after 15 seconds. A timed-out or canceled save
or delete may already have reached the OS store, so its outcome is unknown. Passwords
are not stored in the browser; environment and GPG sources take precedence.

## Interface in 0.9.0

This section describes changes since 0.8.4. Missing configuration is explained
when a lookup needs it. Subnets and IP require Infoblox; Ping and Monitor do not.

A missing credential opens the sign-in dialog for that lookup; see
[Signing in](#signing-in-to-infoblox). The secure-store rules described above still apply.

Each tab retains separate unsent drafts for Subnets, IP, Ping and Monitor across refresh,
including Ping ports. A new independent tab starts with what the tool was last asked in
this session (for Monitor: its targets, ports, interval and duration), or with empty
boxes (Monitor: an interval of 60) when it has not run yet. The example under a box
("For example 192.0.2.1 or 2001:db8::/64") is a line of text read with the box, not a
placeholder.

### Signing in to Infoblox

A lookup that needs a login opens one dialog. Its title says which login: "Sign in to Infoblox
as alice" or, for the device login, "Sign in with your network login" (the user name is shown
only when it is known and fixed; otherwise there is a Username box). It has **Username**,
**Password**, and, when the computer has a secure store, **Remember credentials on this
computer** (unchecked); **Forget saved credentials** appears only while a login is saved.
**Enter** in a box signs in (in Username, while Password is empty, it moves to Password),
**Escape** or **Cancel** cancels, and Tab stays inside the dialog, also when it opened over
another one. A box that is asked for cannot be sent empty: it says "Enter the password." (or
"Enter the user name.") and keeps the focus. Cancel ends the lookup and leaves the application ready for another; focus returns to
the control you used. What you type is read by the browser when you submit and the boxes
are emptied.

After **Sign in** the dialog stays open while Infoblox checks the password ("Checking the
password…"; the boxes cannot be edited then, and **Cancel** or **Escape** stops the lookup).
If Infoblox does not accept the password, the same dialog asks again: it says "Password not
accepted.", the Password box is empty and has the focus, and the user name is kept. A lookup
takes three passwords at most, and the dialog counts them down: "You can try 2 more times in
this lookup. A new password is a sign-in at Infoblox. Repeated refusals can lock the account."
cn-tool does not know your grid's lockout rule, so it says no more than that. **Cancel** in
that dialog ends the lookup like any cancelled sign-in.

After the third password that Infoblox does not accept, the lookup ends with "Infoblox did
not accept the password for alice." and the login is dropped. It ends the same way, without
asking, when the refused login was a saved one (remove it with **Forget saved credentials**)
or one that you typed for an earlier lookup. **Sign in again**, beside that headline on
Subnets, IP and Site Demobilization, puts that lookup back into the form and starts it
again, which asks for a login again, with three tries. Once a login has been accepted, on any page, **Sign in again** is no longer
offered. Remember saves a manually entered login only after a successful lookup, also when
**Forget saved credentials** was selected in the same dialog first.

### Keyboard and Help

**Tab** reaches a skip link first on every page: **Skip to results** moves the focus to the
results (or to the setup card while that shows), and on a page that shows no results it reads
**Skip to content** and moves to the start of the page's content.
The header's **?** button opens **Help**: the page's own notes, the keys, what Stop and Quit
do, and how the report works.

| Key | Does |
| --- | --- |
| `/` | Moves to the first filter field of the page |
| `?` | Opens Help |
| `g` then `s`, `i`, `p`, `m`, `c`, `d` or `t` | Opens Subnets, IP, Ping, Monitor, Configuration Search, Site Demobilization or Settings |
| **Escape** | In a filter's text box that has text: clears the filter; the focus stays in the box |
| **Ctrl+Enter** (**Cmd+Enter** on a Mac) | In Targets, the Monitor form, the search terms or the site: starts, like the button; on the folded line of a form (after Run), runs the same request again, like **Run again** (nothing if the button is disabled) |

`/`, `?` and `g` act only while the focus is not in a box, no dialog or menu is open, and no
Ctrl, Alt or Cmd key is held (AltGr, which some keyboard layouts need for `/` and `?`, is
fine, and Caps Lock makes no difference). After `g`, a key that is not a page's letter does
what it does alone. They are off on the card of a session that has quit or stopped. **Single-key
shortcuts** in Help is a switch that turns them off; it is remembered for the tab (until it is
closed), and Escape and Ctrl+Enter are not affected.

### Moving between pages

Every page (Subnets, IP, Ping, Monitor, Configuration Search, Site Demobilization and Settings)
opens inside the same browser page, without loading it again: the header, the running-job pill
and a message about a job that ended stay where they are, the focus moves to the page's heading
(a screen reader says its name), and **Back** and **Forward** move between them.

- With unsaved changes, Settings asks **Leave Settings and lose your unsaved changes?** before
  a link, a `g` key or **Back** takes you to another page; **Cancel** keeps you on Settings
  with your edits. Choosing the page you are already on asks nothing and keeps your edits.
  If the connection to cn-tool is lost, your browser asks the same question itself, and **OK** loads the other page.
  Reloading the page or closing the tab asks your browser's own question.
- Coming back to Settings in the same tab opens the sections you had open and, after a `g`
  key, scrolls to where you were. Configuration Search shows the same result's table on the
  page, with the filter and the sort you left.
- Coming back to Subnets, IP or Ping in the same tab shows the latest result again with the
  tables as you left them (filter, sort, page) and, on Subnets, the details you had open and
  **Show Available**. What you typed in a form stays too, also after a reload.
- Coming back to the Monitor in the same tab shows the run as it is now (the latest round on
  the Map or the Table, whichever you had, and the round in the pill) and, if you left it on
  **History**, the same list, the same run and the round you had chosen, with the tables'
  filters and **Show Available** as you left them (Show Available's table starts again at its
  first page). The Table's filter and a **Show in table** host stay while the same run is on
  screen. Your form, its folded line and the Map or Table choice stay after a reload too.
- The address in the browser's address bar says what you are looking at: a network's details
  on Subnets, how a result table is filtered, sorted and paged, the Monitor's **History** with
  its saved target, run and round, and an arranged **Table** of the latest round. **Back** and
  **Forward** move between these views inside a page (from a network's details back to the
  summary, from a round back to the run's list, from **History** back to **Live monitor**), and
  a reload opens the same view. Selecting the link of the page you are on keeps its view (on
  Subnets it goes from a network's details back to the summary). The address holds no form
  input: no targets, search terms, site codes or passwords. A table's **Filter** text is part of
  it, since it arranges the table. Opening an address never starts a lookup or a monitor.
- **Copy view link** (on a network's details, beside a run's rounds in History, and beside
  **Copy table** on the result tables of Subnets, IP, Ping, Configuration Search and Site
  Demobilization) copies that address. Opened in another tab
  of the same cn-tool session, it shows the same view of the session's latest result. When the
  result it points to is no longer there (a newer lookup, a deleted run), the page opens plainly
  and says **This link points to a result that is no longer here.** A table that cn-tool pages
  in its worker (Configuration Search, Site Demobilization, a saved round) shows the page the
  address names when you come back to it with **Back** in the same tab. From a link or a reload
  it opens on its first page, with its filter and sort, and the address then says page one. A
  link to a round opens it on whichever page of the run's rounds holds it.
- A lookup, a Ping or a Monitor goes on while you are on another page: the pill and the message
  under the header say that it runs, and coming back to Ping shows the hosts probed so far and
  the progress bar. Leaving a page never stops its job; **Stop** on its page or **Quit** does.
- Leaving Subnets, IP, Ping or Site Demobilization while it asks for a password closes the
  question. If this tab started the lookup and no other tab shows the question, the sign-in is
  cancelled, as **Cancel** in the dialog would. Otherwise the lookup keeps waiting: another tab
  that shows the question can still sign in (this tab does not ask again meanwhile), and when
  none does, the next page that needs the password asks for it again; **Stop** ends the lookup.

### After you run: the form folds

On Subnets, IP, Ping and the Monitor, **Look up**, **Run Ping** and **Run monitor** fold the
form into one line so that the results are on the first screen: how many targets, the first
two of them, then the TCP ports (Ping and Monitor) and, for the Monitor, how often and for how
long ("3 targets: 10.0.0.1, 10.1.0.0/24, … · TCP 22"). The line has:

- **Run again**: starts the same request again, the one the line shows, with the same checks
  as **Run** (it asks for a password when a lookup needs one, and does nothing while another
  job runs or while Run is disabled). **Ctrl+Enter** (**Cmd+Enter** on a Mac) while the focus
  is on the line does the same. If the run cannot start, the form opens and says why.
- **Edit**: opens the form again with what you typed, and puts the focus in Targets.
- **Stop** while the page's own run is going, and **View results** (Subnets, IP and Ping).
  On the Monitor, **Stop** stays in the row above the tabs.

The form folds only when there is something beside it to look at (a result, the hosts probed
so far, or a run of this tool); a run that ends with nothing to show gives you the form back.
The fold belongs to the browser tab: a reload keeps it, a new tab starts with the form open,
and **Ping these** / **Monitor these** open the tool with the form open and the targets in it.
On the Monitor, the latest round is above the form while a run is going.

Pages scroll as a whole, with no box of their own around a table: a table's tools stay at the
top of the window (when the window is at least 600 pixels wide and 500 high) and its header row
stays under them while the rows pass. The Map keeps its own box.

### Light and dark

The pages follow your system's setting: light when the system is light, dark when it is dark.
There is no switch in the page. With Windows high-contrast colours (forced colours) the
buttons, notices, chips and the current page keep an outline, and with "reduce motion" set in
the system nothing on the page moves.

### What a run did

Each tool page says what its latest run did in one banner above the results: a mark, the
headline and, when there is something to do about it, buttons. The mark is an icon and a
word, so it does not depend on colour: **Information** (a result, "Nothing found", nothing
run yet), **Attention** (a run that was stopped, or one with lines not understood, lookup
errors, warnings or probe errors) and **Error** (the run failed). The buttons:

- **Retry** (Subnets, IP, Ping, Configuration Search and Site Demobilization, after an
  error): runs the last request again as it was, Ping with its TCP ports, and puts it back
  into the form. It is not offered once the request is no longer known.
- **Open Settings** (after an error on Subnets, IP, Configuration Search and Site
  Demobilization): opens [Settings](#settings).
- **Sign in again** (see [Signing in](#signing-in-to-infoblox)): offered instead of the two
  above when Infoblox did not accept the login.
- **Show the N lines not understood** (Subnets, IP and Ping): opens the list of the input
  lines that were not understood and moves the focus to it.

Monitor shows its probe-error line and the notice of a run that has ended in the same form,
without buttons.

### Subnets and IP

Subnets keeps the summary and detail workflow described above. Both lookup tools follow
the configured network-view scope and existing IPv4/IPv6 validation and enrichment.
Subnets summaries keep network, status, view and **Details** together in a paged table;
returning from details restores the summary position. **View results** jumps past setup.

From 0.10.0, a **Show Available** checkbox beside the result's buttons lists the addresses that have no record of
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
them. N is the number of targets in the table as it is filtered, on every page: type in the table's **Filter** box
first to send fewer; the numbers follow as you type.
The targets are the rows' addresses, each once, in the table's order; the Subnets summary sends its subnets, one
per line, which Ping and Monitor test host by host as they do for a typed subnet. A row without an address or
subnet is left out and the line beside the buttons says how many; when the filter leaves no row, or no row holds
an address, the buttons stay where they are, disabled, as **Ping these (0)** and **Monitor these (0)**, and the line
says "No row of this table, as filtered, holds an address or a subnet."

Selecting a button opens Ping or Monitor in the same tab, without loading the page again, with the
targets in **Targets** (the Monitor on **Live monitor**, where its form is). Nothing is started:
review the list, add TCP ports or an interval, and select **Run Ping** or **Run monitor**. The list is never
shortened. You are asked to confirm first when the tab already holds different unsent text in that Targets box
(it is replaced), when the targets cover more than 1,024 addresses (the most that TCP ports can be tested for),
or when a subnet is larger than a /16, which Ping and Monitor refuse.

The tool then says, once, in a line under its heading: "9 targets from IP results. Review them,
then select Run Ping." (or **Run monitor**), and puts the focus on the Run button when
nothing else has it. The line goes away when you edit the targets or start the run, and
reloading the page does not show it again.

### Ping

Paste IP addresses, hostnames or subnets, one per line, and optionally enter up to five
comma-separated TCP ports. Hostnames use system DNS with IPv4 preferred over IPv6.
ICMP uses the system `ping`; if it is unavailable, a TCP selection still runs and marks
ICMP as not run. The [ping limits](ping-monitor.md#bulk-ping-cn-ping) also apply here.

Invalid targets and DNS failures are separate from completed rows. Results show 25 rows a
page at first and keep the rows per page you choose for the next result; **Rows per page**
offers 5 to 100 and **All (up to 1,024)**. Diagnostic lists use pages of up to 50 items, with
page-number entry.

While a Ping runs, a progress bar says how many hosts have been probed ("300 of 1,024"),
and the hosts probed so far appear below it in a table, **Ping hosts so far**, under the
line "Hosts probed so far. The final result replaces these rows." The rows arrive in place,
so a filter or a sort you set there stays. They are not a result: the table has no
download or copy, and when the run ends its result takes their place. A run that is
stopped before a row was kept, or that fails, leaves none of them behind, in this tab, in
another tab or after a reload, and the earlier result, if any, is shown again. Stop waits for DNS and active probes to drain and distinguishes incomplete from
unattempted hosts. Earlier useful results remain available when a new attempt yields none.

Ping results use one compact table on desktop and narrow screens, with the target,
ICMP result and TCP results (each a small label: OK, NO RESPONSE, open, closed, timeout)
grouped together; the buttons above it narrow it to one outcome. Scroll inside the table for additional
columns, or use **View results** to jump past setup. The target input scrolls when a
large list is pasted. Diagnostic sections show their counts and can be expanded; they
open automatically when the latest attempt has no completed results. Expanding or
paging diagnostics preserves the other sections' state.

### Monitor

Monitor repeatedly probes the same kinds of targets. Interval defaults to 60 seconds;
leave duration blank to continue until stopped. Both supplied values must be at least
10 seconds, and duration must be at least the interval.

A line above the live view gives the run: the latest complete round and when it began
("Round 31 · 10:39:50 UTC"), then, while it runs, what it does now (a countdown, "next in", while
it waits, or its stage and count, "probing 120 of 320"), then its start, its hosts, its
TCP ports and its interval ("since 10:34 UTC · 320 hosts · TCP 22 · every 10 s"). All times
are UTC; a date comes first when it is not today. When a run has ended, a line says how:
"Stopped 10:43:18 UTC after 52 rounds. Showing the last round." (**Finished** for a run that
reached its planned end).

The latest complete round uses bounded pages. This run's and earlier round counts are
shown separately; an incomplete first round is not an outage. History is a changing view
of recorded requests, runs, rounds and hosts, and refreshing it starts at page one.

#### Map and Table

From 0.12.3, the latest complete round has two views, chosen with **Map** and **Table** above it. The page
opens on the **Map**; a tab remembers the view it was given, across a refresh, and a new tab
starts on the Map again.

The Map is the live view of [`cn monitor`](ping-monitor.md#ping-monitor-cn-monitor) in the
page: one character for each address, in address order, one block for each subnet line (rows
of 64, 32 or 16 addresses, in groups of 8, each row labelled with its first address) and a
`Hosts` block for single addresses and names. It shows every host of the round. Filters, sorting
and paging belong to the Table, and what is chosen there does not hide anything on the Map.

| Character | Meaning |
| --------- | ------- |
| `!` | replied; underlined, in the warning colour, when only some echo requests were answered |
| `R` | rejected: the host itself sent an ICMP error, so it is up, behind its own firewall |
| `T` | silent to ping, but a TCP port answered |
| `x` | gone: not seen in this round, but seen earlier |
| `U` | unreachable: never seen, and an ICMP error came from another address; it stays until the host is seen |
| `E` | the probe failed |
| `?` | the name did not resolve |
| `.` | silent: no answer |
| blank | not probed yet, or not a host of the run (a network or broadcast address) |

A character in reverse video changed in the last round (the host came or went). The characters
carry the meaning and the colours only add to it; the legend under the Map lists all of them.
The counters line above it reads as on the command line, for example
`12 replying · 1 unreachable · 2 gone · 15 seen of 254`.

- **Details.** Point at a character for its address and state at once, then its latest result,
  TCP ports, **Last seen**, **First seen**, the rounds it answered and since when it has been
  seen or gone. Click or tap the character to keep the details open: they then have **Copy IP**,
  **Show in table** (opens the Table filtered to that host) and **Close**. Escape, or a click or
  tap elsewhere, closes them. The times in the details are in UTC.
- **Keyboard.** The Map is one stop in the tab order. The arrow keys move a cursor from
  character to character and show its details, Home and End go to the ends of a row, Page Up
  and Page Down to the neighbouring block, Enter or Space keeps the details open and Escape
  closes them. The details are announced to a screen reader as they are shown, and again after
  a round only when something other than **Last seen** and **Answered** has changed; the Table
  holds the same round as rows and columns.
- **Rounds.** The Map shows complete rounds only, like the Table, so it changes once per
  interval and never shows a round in progress. A new round redraws only the rows that changed:
  the scroll position, the cursor and open details stay.
- **Blocks with answers.** When the Map has two blocks or more, **Previous block with answers** and **Next
  block with answers** stand above it. They go to the nearest block in which a host answered (`!`, `R` or `T`),
  passing over the silent ones; nothing is hidden. In a block that is drawn the cursor lands on the first host
  that answered; a block that is only a counter line is outlined. A line beside the buttons says where you are,
  for example "Block 3 of 3, 10.3.0.0/28: 1 of 14 answering. Cursor on 10.3.0.2.", or "No later block has
  answers."
- **Large runs.** Up to 65,536 addresses are drawn (one /16). Beyond that, each subnet line is
  one counter line, as on the command line when the grid does not fit the terminal
  (`10.0.0.0/16: 3 ! · 61,102 .`), with **Show this block** to draw that subnet alone. The `Hosts`
  block is drawn up to 2,048 names, and a long name makes the Map wider.
- The Map is text: it can be selected, copied, searched with the browser's find, and printed.
  Round-trip times are not measured, so none is shown.

The latest-round, saved-round and Show Available host tables are tables like the others
(see [Sorting and filtering](#sorting-and-filtering-results-in-093)): one **Filter** box over
every column, buttons for each outcome with their counts, **Rows per page** (5 to 100 and
**All (up to 1,024)**; 25 at first) and **First**, **Previous**, **Next** and **Last**
(a saved round has no **Last**: it is read page by page). Changing the page size returns to
the first page and keeps the sort and the filter; each table keeps its own size. Each new
round updates the latest-round table while you are in it: the focus, the scroll position,
a selection in a row that did not change, the sort and the page stay. If a new round has
fewer matching hosts, the table moves to its last page.

### Download table (CSV) and Copy table

From 0.12.0, the Ping results table and the Monitor latest-round, saved-round and Show Available host
tables have **Download table (CSV)** and **Copy table** above them, and so has every table of Subnets and IP. Both take the whole
table as it is filtered and sorted, every page, with the columns and headings on screen
(Ping has one column per TCP port; Monitor one TCP column).

- **Download table (CSV)** saves a comma-separated file that Excel opens with a
  double-click (UTF-8 with a byte-order mark, so `—` and `09:00–09:41` read correctly).
  Its name says which table and when, for example `cn-ping-20261112-090507.csv` or
  `cn-monitor-round-20261112-090507.csv`.
- **Copy table** puts the same rows on the clipboard as tab-separated text, so that they
  paste into separate cells of an existing sheet. If the browser does not allow the copy
  (for example because another window had the focus), return to the tab and select
  **Copy table** again. A table too large to copy says so at once; download it instead.
- The configuration matches table has one more column in the file than on screen: **Search**, the term
  or network that found the row (the screen says it once, in the line above the table).
- A cell that starts like a formula (`=`, `+`, `-`, `@`) and is not a number gets a
  leading `'`, so a host name never runs as a formula.
- For a Ping run that was stopped or is still running, the export includes the completed
  results and says so.
- On Monitor, a large table is read page by page: progress is shown and **Cancel** stops it
  ("Cancelled. Nothing was downloaded."). The file holds the table as it was when you
  selected the button, and the table stays in use meanwhile. A new live round arriving
  meanwhile stops it with a message; download again. **Download available IPs**
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

Closing a tab or navigating away leaves this session's monitor running. **Stop this session’s monitor**
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
and results are not saved in browser storage or URLs (the address holds only how the matches table is
filtered, sorted and paged, never a search term or a match); the Site Demobilization confirmation
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
The matches are a table with the **Filter** box and the footer of every table (up to
**All (up to 1,024)** rows a page): **Device**, **Line (from 0)** (line numbers start at
zero, as in the workbook and on the command line), **Matching configuration**, with what
matched highlighted (the search worked it out, so a long line or an odd pattern never slows the page), and **File**, with **Copy path**, which copies the file's full path
("Path copied."). While the table is in the search's order or sorted by device, a line
before each device's matches names it and counts them ("EDGE-1 · 12 matches", under the
filter, on every page). One line above the table says what was searched
("Search: 192.0.2.0/24, router-name"). On a screen of 600 px or wider the device stays in
view while the table scrolls sideways. **View matches** jumps past setup. The header's **Help** button (?) explains syntax and limits; Ctrl+Enter starts the search. Diagnostic counts expand into
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
or **Cancel** to end the check without scanning. Consent is available after a preview
page has loaded; the browser does not choose the networks or repository paths for the scan.

A check can search at most 200 distinct IPv4 networks. IPv6 and invalid network records
are skipped with notices. If discovery is incomplete, the warning remains visible during
the search and with the results; the check is partial and its report is not saved.
The preview's networks and the matches are tables with the **Filter** box and the footer of
every table (up to **All (up to 1,024)** rows a page). The matches are the table of
[Configuration Search](#configuration-search): by device, **Line (from 0)**, the match
highlighted, **Copy path** for the file. Result headings identify the site and earlier
results when available.
Cached configuration mode is unavailable in this interface and is refused on confirmation.

The configured network view applies. If no view is configured, the search uses the
views available to the account; if the view list is denied, the preview warns that access
is limited and retains available view labels. Incomplete view discovery and a denied
configured view stop the preview. The preview remains available across navigation or
reload in the same live session for up to five minutes. Cancel, a replacement lookup,
Stop, Quit or expiration invalidates it; confirmation can be used once. Automatic
reports and accumulated workbooks can contain full device configurations and earlier
results, so handle them as sensitive.

## Settings

From 0.12.0, **Settings** (in every page's tool links, and under **Setup required** on the pages that show it)
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

**The Report menu** is a button in the header of every page, between the running-job pill and **Quit
application**. It opens a small panel with one line about the workbook (`cn-report.xlsx · contains earlier data`,
`No report yet`, `Reporting is off`), the sentence "Download copies the report as it is once pending saves have
finished.", **Download accumulated report**, **Delete report…** and one status line for what the download or the
deletion is doing. The workbook is shared by all the tools, so the menu is the same on every page; a page says about the
report only what its own latest run did to it, inside its result: nothing when no save was due, **Saved to the report.**
after a save and **Not saved: <reason>.** when a save was due and did not happen (a Ping with a probe that ended in
error is not saved, and says so). **Escape** closes the menu and focus returns to the Report button.

**Delete report…** (from 0.11.0) closes the menu and asks first. Its confirmation names the report file (the file name
only) and says that it removes the whole accumulated report shared by all the tools,
including the sheets of the other tools. Results on screen, Monitor history and the
copies already prepared or downloaded stay. So do the **Download available IPs**
lists, which come from Infoblox results and the Ping history, never from the
workbook. The next saved results create a new report.

Deletion is offered only while nothing is running, no report write is pending and no
report download is being prepared. The application checks again when you confirm and
refuses if work has started in another tab meanwhile. While it runs, every open tab
shows its progress (the banner under the navigation, and **Deleting report…** in the menu), operation starts and report
downloads are disabled in all of them, and **Quit** stays available. When it ends the tab that asked shows a message
(**Accumulated report deleted.**, **No accumulated report exists.** or the reason it failed) and the menu of every tab
says **No report yet**; no tool shows an older save again until a later operation saves; that save enables download and
delete again.

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

**Download accumulated report** (in the Report menu) waits for pending writes and downloads a consistent copy of the
existing workbook. It does not enable reporting or save a selected view. After a failed
or disabled save, the downloaded file may contain only earlier results. The accumulated
workbook may hold earlier sensitive information as well as the current result.

**One operation at a time.** While a tool works, the other tools wait. A pill in the
header of every page names the running job, how far it is (a Ping's hosts probed, a
Monitor's round) and how long it has run. Every page that
does not own the job shows a banner under the navigation: what runs, since when (UTC),
and that other tools wait until it finishes (for a Monitor: until it stops), for example
"Monitor is running: 320 hosts, since 10:34 UTC. Other tools wait until it
stops." Both lead to the tool that owns the job. The page's start button stays disabled
meanwhile, and the page says once when the job has ended. The status line of the page
that owns the job reads **Running:** with the stage (and the count, for Ping and
Monitor), with the elapsed time beside it.

**Stop** is shown only on the page of the tool that owns the running job, and it ends
only that job: **Stop lookup** on Subnets and IP, **Stop Ping**, **Stop search**,
**Stop site check** and **Stop this session's monitor**. No page can stop another tool's
job. Stop cooperatively prevents new work after in-flight requests finish within configured
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

Quit closes at once when nothing would be lost. Otherwise it asks first, with **Cancel**
selected, and names each thing it will do:

- a running Subnets, IP or Ping lookup is finished and saved before the application closes;
- a running Monitor is stopped and saves what it has;
- a running configuration search or Site Demobilization check is stopped, and its results
  are not saved;
- a report save in progress is waited for;
- a report download that is being prepared is cancelled;
- a report deletion that has not finished is cancelled, so the report can stay;
- unsaved changes on Settings are lost;
- then the configured exit actions run (for example the report e-mail) and the
  application closes.

After Quit every open tab shows one card: cn-tool has quit, the tab can be closed, and
`cn-web` or the cn-tool Web shortcut starts it again. No tab offers to reconnect.

Closing a tab does not run exit actions. An unexpected worker failure is displayed
without rerunning work or replaying email: the tools show one card with the reason and
**Quit application** (a failed session still runs until Quit, and starting `cn-web` would
reopen it), while Settings stays usable. Ctrl+C also stops a local WebUI session
cleanly on Windows (from 0.8.4; 0.9.0 to 0.11.0 also printed a traceback from a
background process as they ended, which 0.11.1 removes); interruption skips normal
exit actions inappropriate for a canceled session.
