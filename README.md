# cn-tool

`cn-tool` is a modular network utility for Infoblox lookups, bulk network
checks, configuration repository searches, and device inventory collection. It runs on Linux, macOS
and Windows (natively, without WSL) and installs with `pipx install cn-tool`.

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

## Included Features

- IPv4 and IPv6 address, subnet, FQDN, and location lookups using the Infoblox API; a site is found
  by an Infoblox extensible attribute (`[site] ea_name`) or by subnet comment; an object held in
  several network views is listed once per view, and `--view NAME` limits a lookup to one
- Command line (`cn subnet|ip|fqdn|site|ping|diff|doctor`) with table, JSON, Markdown and CSV
  output and exit codes for scripts, and `cn init` to write a starting configuration
- Bulk ping (IPv4 and IPv6) with an optional TCP port check, resolve, and (on Linux and macOS)
  traceroute operations
- `cn diff`: which snapshot of a device added or removed a configuration line, and who made it
- `cn doctor`: configuration, credential and Infoblox WAPI checks
- Configuration repository search with optional SD-WAN YAML enrichment
- Device inventory queries in parallel (Cisco IOS/IOS-XE and NX-OS, platform autodetected)
- Config repository browser TUI (`python -m config_analyzer`)
- Active Directory subnet enrichment
- Excel report generation and optional email delivery
- Disk-backed cache for faster repeated lookups

## Installation

cn-tool needs Python 3.10 or newer, on Linux, macOS or Windows 10 and 11 (x64). On Windows, Python
3.12 to 3.14 is recommended (see [Windows](#windows)). The test suite runs on all three systems
(macOS once a week). The macOS `ping` and `ping6` were run on a real Apple-silicon Mac runner (macOS
26); a silent IPv6 host, Intel Macs and older macOS versions have not been run.

### From PyPI

[pipx](https://pipx.pypa.io/) gives cn-tool a virtual environment of its own and puts its commands
on your PATH. On Windows, `py -m pip install --user pipx`, then `py -m pipx ensurepath` and a new
terminal install pipx itself.

```bash
pipx install cn-tool
cn --version
```

Or install it into a virtual environment you manage:

```bash
python -m venv .venv
source .venv/bin/activate      # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install cn-tool
```

Either way you get the commands `cn` and `cn-tool` (the same program) and `python -m cn_tool`. If
another program on your PATH already provides a `cn` (the npm package of that name does), use
`cn-tool`. Upgrade with `pipx upgrade cn-tool`, or `pip install --upgrade cn-tool`.

### From the zip or a clone

Unpack the zip of a release (or clone the repository), create a virtual environment, and install the
dependencies:

```bash
pip install -r requirements.txt
python main.py
```

`pip install .` in the same directory gives the same install as from PyPI. When you upgrade a zip,
unpack it into a new, empty directory: the code lives in a `cn_tool` folder now, and the release
notes of 0.7.0 say what to move.

On a shared server where users cannot write to the install directory, run
`python -m compileall -q /path/to/cn-tool` after each unpack or update, with the Python that runs
`cn`. Python cannot cache compiled modules in a read-only directory, so without this step it
compiles every cn module on every start: about 0.14 s more for a lookup (0.42 s instead of 0.28 s
on a shared dev host, measured with 0.4.1). A pip install compiles its files when it installs.

### First run

```bash
cn init
```

writes a commented starting configuration to `~/.cn` (`%USERPROFILE%\.cn` on Windows). It never
overwrites a file: it exits 2 and changes nothing when `~/.cn` exists. Open the file in a text editor
(`notepad $HOME\.cn` on Windows), remove the `# ` in front of `endpoint` in `[api]` and set your
Infoblox grid, and save the file as UTF-8. Then run:

```bash
cn doctor
```

It checks the configuration, the credentials and the Infoblox WAPI. While no configuration file
exists at all, `cn doctor` (a `Config file` row first), the menu's start-up warning and a refused
command-line lookup tell you to run `cn init`; the `.cn` in the root of a zip or a clone counts as
a configuration file, so only a pip install sees these hints.

Edit `~/.cn` in a text editor, not through the menu's Application Setup (`s`): Setup rewrites the file
without its comments. The rest of the configuration is described in [Configuration](#configuration).

## Windows

cn-tool runs natively on Windows 10 and 11 (x64), in Windows PowerShell 5.1 and in PowerShell 7,
without WSL. The commands on this page are for PowerShell.

### Terminal and Python

- **Terminal.** Windows Terminal is recommended; the older console window works too, though spinner
  glyphs may show as boxes there. In Warp (warp.dev), typed text at a line prompt such as Bulk Ping's
  can be drawn over the line above the cursor; plain PowerShell and the ordinary console are not
  affected, and no cause in `cn` was found (the likely one, a cursor move that Windows' pseudo-console
  sends after the menu's alternate screen, is inferred, not confirmed in Warp): use Windows Terminal or
  PowerShell. The menu needs a real console: the terminal of Git Bash is not
  one, so `cn` alone refuses to open the menu there (`cn: no command given and no terminal for the
  menu`) and exits 2; run `winpty cn`, or use Windows Terminal. A command such as `cn ip 10.1.2.3`
  works anywhere.
- **Python.** Install it from python.org or with the Python install manager; both provide the `py`
  launcher. The Microsoft Store Python works but has no `py`: write `python -m pip` where this page
  says `py -m pip`. Python 3.12 to 3.14 is recommended: Python 3.15 was too new for PyYAML's Windows
  wheel when 0.7.0 was released, so pip would need a compiler there. On Windows on Arm, install the
  x64 Python; cn runs under emulation.
- **When `cn.exe` is blocked** by AppLocker or antivirus: `py -m pip install --user cn-tool`, then
  `py -m cn_tool` with the same commands and options (`py -m cn_tool ip 10.1.2.3`). A pipx install
  keeps cn-tool in its own environment, so `py -m cn_tool` finds nothing there.

### Passwords in PowerShell

PowerShell's PSReadLine saves your command lines in plain text in
`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, except lines that
contain words such as `password` or `secret`. So never type `$env:TACACS_PW = 'secret'`. For one
terminal, without leaving the password in the history file:

```powershell
$env:TACACS_PW = Read-Host 'TACACS password' -MaskInput
```

(PowerShell 7.1 and later), or, in Windows PowerShell 5.1, which has no `-MaskInput`:

```powershell
$env:TACACS_PW = [Net.NetworkCredential]::new('', (Read-Host 'TACACS password' -AsSecureString)).Password
```

Or leave it unset: `cn` asks, without echo, when it needs it. `setx TACACS_PW …` is worse:
- it stores the password in plain text in the registry (`HKCU\Environment`);
- every program you start later can read it;
- it roams with a roaming profile;
- the terminal you typed it in does not see it.

Use `setx` for names only (`setx INFOBLOX_USER svc-ipam`). Remove a stored password with
`[Environment]::SetEnvironmentVariable('TACACS_PW', $null, 'User')`. The same holds for
`INFOBLOX_PW`.

The device login's user name is read from `USERNAME` (Windows has no `USER`). If your device login
is not your Windows user name, put it in a variable of your own (`setx CN_USER alice`, a name is
not a secret) and name that variable in `.cn`:

```ini
[auth]
device_user_var = CN_USER
```

### Scheduled tasks

A Task Scheduler task sees only the environment that is stored for its account, and it cannot show
gpg's passphrase window: gpg waits out its 90 second timeout, and a device GPG file older than 24
hours is ignored. Keep the password with DPAPI, which only your account on that computer can read:
once, in a normal PowerShell session,

```powershell
Read-Host 'TACACS password' -AsSecureString | ConvertFrom-SecureString | Set-Content $HOME\.cn-tacacs
```

and in the task's script, before `cn`:

```powershell
$env:TACACS_PW = [Net.NetworkCredential]::new('', (Get-Content $HOME\.cn-tacacs | ConvertTo-SecureString)).Password
```

To save text from a task, redirect through `cmd`: `cmd /c "cn ping 10.1.2.0/24 --format csv > out.csv"`
(see [Output and encoding](#output-and-encoding)).

### GPG credentials file

Install [Gpg4win](https://www.gpg4win.org/) for `-g` and `[gpg]` files, and open a new terminal so
that `gpg` is on the PATH; without it `cn` says `gpg is not installed (install Gpg4win, then open a
new terminal)`. gpg-agent asks for the key's passphrase in Gpg4win's window. Make the credentials
file in an editor such as Notepad, saved as UTF-8, encrypt it, and delete the plain copy:

```powershell
notepad $HOME\cn-tool-credentials.txt     # two lines: User = alice and Password = ...
gpg --encrypt --recipient YOUR_KEY_ID --output $HOME\cn-tool.gpg $HOME\cn-tool-credentials.txt
Remove-Item $HOME\cn-tool-credentials.txt
```

One way of writing the file fails in Windows PowerShell 5.1: `>` and a plain `Out-File` write UTF-16,
and `cn` then says the file `could not be decrypted by gpg --batch`. Notepad, `Set-Content -Encoding
utf8`, `Out-File -Encoding utf8` and `[IO.File]::WriteAllText($path, $text)` write UTF-8, and so do
`>`, `Out-File` and `Set-Content` in PowerShell 7. A byte-order mark at the start of the file, which
Windows PowerShell 5.1 adds to `-Encoding utf8` output, is dropped when `cn` reads the decrypted text.

### Output and encoding

`cn` writes UTF-8 on Windows, also when its output is redirected or piped. PowerShell (5.1 and 7)
decodes a program's output with the console's code page (`[Console]::OutputEncoding`, the OEM code
page: 850 or 437, for example), so a name such as `Zürich` comes out garbled in
`cn … | ConvertFrom-Json` until you run `[Console]::OutputEncoding = [Text.UTF8Encoding]::new()`
(put it in your `$PROFILE` to keep it). Windows PowerShell 5.1 also writes `>` redirections as
UTF-16, which other tools may not read: let `cmd` redirect instead (`cmd /c "cn doctor > out.txt"`
writes UTF-8; PowerShell 7's `>` writes UTF-8 too). Save `.cn` as UTF-8 as well (see
[Configuration](#configuration)). The tables use box-drawing characters, so whatever reads them
must read UTF-8.

### Files, reports and certificates

- **Where files go.** `C:\Users\<you>\.cn`, `cn.log`, `report.xlsx` and the `.cn-cache` folder sit in
  your profile folder, which OneDrive does not sync. The keys move them; on a roaming profile,
  `[cache] directory = ~/AppData/Local/cn-tool/cache` keeps the cache off the network. `pipx
  uninstall cn-tool` leaves these files behind.
- **A report open in Excel.** Excel locks a workbook it has open, so a lookup cannot save to it.
  `cn` says `Error: Could not write the report: C:\Users\alice\report.xlsx is open in another
  program (Excel?). This result is not in the report; close the file before the next lookup.` The
  result is dropped, not retried, and a command-line run exits 3.
- **Certificates.** `requests` trusts the certificate bundle that ships with it, not the Windows
  certificate store. Behind a proxy that inspects TLS, point `REQUESTS_CA_BUNDLE` at your
  organisation's CA bundle (`$env:REQUESTS_CA_BUNDLE = 'C:\certs\corp-ca.pem'`), or turn off
  `[api] verify_ssl` (which disables the check).
- **SSH to devices.** A bastion named by `ProxyJump` in `~\.ssh\config` runs Windows' OpenSSH client
  (`ssh.exe`), which Windows 10 and 11 include as an optional feature.

### What differs from Linux

- Bulk PING runs Windows' own `ping` (see [Bulk ping](#bulk-ping-cn-ping)). An IPv6 target that this
  computer has no route to reads `NO RESPONSE`, not `NO ROUTE`.
- Bulk Network Trace (menu item `t`) is not available: it needs `mtr`, which does not exist on
  Windows. `cn` says `Bulk Network Trace needs mtr, which is not available on Windows.` and returns
  to the menu.
- On Python before 3.14, Windows may not interrupt a bulk run that is waiting for its probes (a
  Python limitation that 3.14 fixes). If Ctrl-C does not stop it, close the window, or use Python
  3.14.
- On the command line, give a file of objects with `--file`, not `< file`: PowerShell reserves `<`.

## Command line

`cn <command>` runs one lookup without the menu, prints the result on stdout and exits with a
status a script can test. Without a command the menu opens as before.

```
cn [global options] <command> [objects…|-] [--file PATH|-] [--format table|json|md|csv] [--report]
```

For scripted use, call `cn` from the PATH (a pip install puts it there) rather than a shell alias,
which is not expanded in scripts, cron jobs or `ssh host cmd`. From a zip or a clone, install a
symlink instead of calling `python main.py` (on Windows, `pip install .` installs the `cn` command):

```bash
ln -s /path/to/main.py ~/bin/cn
```

| Command  | Objects | Returns |
| -------- | ------- | ------- |
| `subnet` | `10.1.2.0/24`, `10.1.2.0/255.255.255.0`, `2001:db8:20::/64` or an IP address (its subnet); a container prefix expands to its subnets and lists its child containers, not expanded | subnet summary with DHCP utilization %, DHCP ranges, DNS records, fixed addresses, extensible attributes (an IPv6 subnet has no DHCP utilization or failover); a `child containers` table for a container prefix; one summary row and one set of details per network view that holds the subnet |
| `ip`     | IPv4 and IPv6 addresses | network view (on a grid with several), subnet, DNS name, status, MAC (IPv4), DUID (IPv6) and PTR name, one row per network view that holds the address; an unused IPv4 address is reported as `UNUSED` |
| `fqdn`   | names or name prefixes (at least three characters) | A, AAAA, host and CNAME records whose name contains the text, with type, DNS view (on a grid with several), zone, TTL and a PTR check |
| `site`   | site codes; with `-k/--keyword`, keywords | the subnets of each site code, or matching each keyword, with DHCP utilization % and, on a grid with several network views, the network view |
| `ping`   | IPv4 and IPv6 addresses, host names, `10.1.2.0/24` and `2001:db8::/120` networks | ICMP result per host and, with `--tcp 22,443`, the state of each port |
| `diff`   | device names, as in `<name>.cfg` in the configuration repositories | configuration lines added or removed since the last change or `--since`, with the snapshot, author and time |
| `doctor` | none | one row per configuration, credential and Infoblox check |
| `init`   | none | nothing on stdout: it writes a commented starting configuration to `~/.cn` and never overwrites a file (exit 0 written, 2 the file exists, 3 it could not be written) |

`site` results are paged: up to 10,000 subnets per address family (IPv4 and IPv6 networks are
fetched separately); at the cap a warning says so. `fqdn` pages each record type (A, AAAA, host,
CNAME) and its PTR search up to 10,000 rows.

`ip`, `subnet`, `fqdn`, `site` and `doctor` add `--view NAME` and `--all-views` (see
[Network views](#network-views)). `ping` adds `--tcp PORTS`, and `diff` adds `--since WHEN` and
`--line TEXT`. `doctor` and `init` take neither objects nor `--file`. `diff`, `doctor` and `init`
write no report: they have no `--report`, and `-r FILE` is refused with exit 2. An option name is
never abbreviated (`--rep` is an error, not `--report`).

Objects are arguments, or one per line from `--file PATH`; a positional `-` or `--file -` reads
standard input (in PowerShell use `--file`: it reserves `<`, so `cn subnet - < scope.txt` is not
possible there). Blank lines and `#` comments are ignored. Global options (`-c`, `-nc`, `-t`, `-l`,
`-r`, `-g`, `--log-level`) work before and after the command. `cn <command> --help` shows the
details of one command.

A command loads only the libraries it uses: pandas and openpyxl when it saves a report, netmiko
(with paramiko) when it queries a device over SSH, ldap3 when Active Directory connects, yaml for
the SD-WAN YAML search and diskcache for the cache. On a shared dev host (2 cores, load 2-3)
`cn --help` starts in about 0.15 s and `cn ip` reaches its credentials check in about 0.28 s;
before 0.4.1 they took about 0.5 s and 0.9 s. The menu starts faster for the same reason.

A bare object is routed by its shape: `cn 10.1.2.3` or `cn 2001:db8::5` runs `ip`, `cn 10.0.0.0/24`
or `cn 2001:db8:20::/64` runs `subnet`, `cn host.example.com` runs `fqdn`. Only an IPv4 or IPv6
address, a network of either family or an FQDN is recognised, and the two families mix inside one
kind (`cn 10.1.2.3 2001:db8::5` is `ip`). A MAC address, a partial address such as `10.1.2`, a
bracketed address (`[2001:db8::1]`) and a mix of kinds exit 2. `ping`, `diff` and `doctor` are
never inferred: use `cn ping 10.1.2.3 --tcp 443`.

### PTR, DHCP utilization and child containers

`fqdn` returns one row per address: `ip`, `name`, `type` (`A`, `AAAA`, `HOST` or `CNAME`),
`canonical` (a CNAME's target), `DNS view` (only on a grid with several DNS views, or with a view
selected), `zone`, `TTL` (empty = the zone default) and `PTR`. Rows are sorted by name, type,
address and DNS view, and a record held in several DNS views is listed once per view. Five requests
run for each prefix: the four record types and the PTR records of the same names.

| `PTR` | Meaning |
| ----- | ------- |
| `ok` | a PTR record on the grid at this address, in the record's DNS view, points back to the name (in any DNS view for a row without one) |
| `missing` | no such PTR record does, in the record's DNS view (in any DNS view for a row without one); `cn ip <address>` shows the PTR the address has |
| `host record` | the host record is configured for DNS, so it publishes its own PTR; not checked |
| *(empty)* | a CNAME row, or the PTR check could not run (a warning says why) |

A host record that is not configured for DNS (DHCP/IPAM only) is checked like an A record: `ok` or
`missing`. A record type whose search fails adds a `warnings` row and makes the status 3; the other types are
still listed. `ip` adds `PTR name` (one extra request per address that has a PTR record; a failed
lookup is a warning and status 3); on a grid with several network views a row shows only the PTR
records of its own network view.

`subnet` and `site` show `DHCP utilization %`: the WAPI `dhcp_utilization` value taken as per mille,
so divided by 10, with one decimal. `subnet` leaves it empty for a subnet without a DHCP range and
adds `utilization %`, `utilization status`, `leases`, `static` and `total` to each DHCP range;
`site` does not read ranges, so a subnet without one shows `0.0` there and IPv6 rows are empty.
Infoblox has no DHCP utilization for an IPv6 network or range, so those cells are empty for an IPv6
subnet too, and it has no `DHCP failover` rows. An input shorter than /30 (IPv6: /126) also lists
its child containers (`container`, `child container`, `comment`, `utilization %`); they are not
expanded, so query one to see its subnets.

### Network views

A network view is an Infoblox partition of the IP space: the same network, address or name can
exist in several views, each with its own data. A grid with one view has nothing to choose, and
nothing changes there.

By default `ip`, `subnet`, `fqdn` and `site` search every network view and list one row per view
that holds the object. A WAPI search without a view answers across every view, so this costs no
extra request; `cn doctor` tests that on a grid with several views. Choose one view instead with:

| Choice | Effect |
| ------ | ------ |
| `--view NAME` | search only this network view (matched exactly; `cn doctor` lists the names) |
| `--all-views` | search every view, even when `[api] network_view` is set |
| `[api] network_view = NAME` | the view every lookup searches when no option is given, in the menu too; empty (the default) searches every view |

`--view` and `--all-views` work on `ip`, `subnet`, `fqdn`, `site` and `doctor` (the last one given
wins), then `[api] network_view`, then every view. `--view ""` is refused (exit 2); `ping` and
`diff` take neither option. One view can be named at a time.

```bash
cn ip 10.20.0.5 --view lab
cn ip 2001:db8:20::5 --view lab
cn subnet 10.20.0.0/24 --all-views --format json
cn site syd --view prod --format md
cn fqdn web01 --view lab
cn doctor --view lab
```

**The view column.** `ip` shows `Network view` first; `subnet` shows `Network view` in the summary
(after `Original Input(s)`) and `network view` first in its detail sections; `site` shows
`network view` first; `fqdn` shows `DNS view` before `zone`. In `table`, `md`, `csv`, the menu and
the xlsx report the column shows when a view is selected, when the grid has more than one network
view (`fqdn`: more than one DNS view), when the rows of a run name two views, or when the grid's
list of views could not be read. Otherwise it is left out, so a grid with one view prints what
0.3.0 printed. JSON always carries `network_view` (`fqdn`: `dns_view`) in these rows, on every
grid, so a script that counts rows on a multi-view grid should key on it:

```bash
cn ip 10.20.0.5 --format json | jq -r '.ip_information[] | "\(.network_view) \(.subnet)"'
```

- **`ip`**: one row per address and network view. The PTR request is still one per address. A PTR
  record goes to the row of the network view that holds its DNS view; one whose DNS view is not
  listed goes to every row. A PTR record in a DNS view of a network view where the address has no
  row is not shown.
- **`subnet`**: four requests per network, however many views hold it. The answers are split by
  view into one summary row and one set of details per view. The 10,000-row cap of a list is shared
  by the views, and the warning names them (`shared by network views default, lab`). The menu
  names the view (`Details [2/2] for: 10.20.0.0/24 in network view lab`), and the "Subnet Data
  Detail" sheet gets `Network view` on every row.
- **`site`**: one row per network and view, in the grid's order.
- **`fqdn`**: rows are sorted by name, type, address and DNS view, and a record in two DNS views is
  two rows, also on a grid with one network view and split-horizon DNS (`internal`, `external`).
  The `PTR` verdict is checked in the record's own DNS view, so an `external` record with no PTR
  in `external` reads `missing`.
- **`fqdn` with a view**: A, AAAA, CNAME and PTR records are searched in each DNS view of the
  network view and host records by network view, `1 + 4k` requests for k DNS views (5 without a
  view). If the PTR search of one DNS view fails, only that view's `PTR` is left empty, and an
  IPAM-only host may then read `missing`. A view with no DNS view searches host records only, and
  stderr says so.

A selected view is checked after the login and before the first lookup (in the menu, before any
input, with a banner naming the view). A view that is not on the grid exits 2 with
`no network view 'prd' on the grid (--view); network views: default, prod, lab`; a name that is a
DNS view's says `use --view <network view>`, and a name that differs only in case says
`did you mean 'prod'?`. If the list of views cannot be read while one is selected, the exit is 3
with `check with: cn doctor`. With no view selected an unreadable list is not a failure: the lookup
runs without a view and the column shows.

`cn doctor` adds a `Network view` row after `Site attribute`: the grid's views, the view the lookups
search and, for a selected view, its DNS views. On a grid with several views and none selected it
runs a probe (two requests): it asks the first non-default view for one network, then asks for that
network without a view; if the answer does not name that view, the row is a `warning`. The Setup
menu status block has an offline `Network view` row (`every view ([api] network_view not set)`).

The list of views is one small request, read at most once per lookup and only when `[api] endpoint`
is set and the answer needs it. `ip` and `site` send the requests they sent before, `subnet` four
per CIDR, `fqdn` five per name.

### IPv6

`ip`, `subnet`, `ping` and Bulk DNS Lookup take IPv6 addresses and prefixes, in the menu and on the
command line, and so do bare objects. `fqdn` and `site` always did. Network views work unchanged.

```bash
cn 2001:db8:20::5 2001:db8:20::1:a --format md
cn subnet 10.20.0.0/24 2001:db8:20::/64 --format json
cn ping 2001:db8:20::5 web06.example.net --tcp 443
cn ping fe80::1%eth0
```

An IPv4-only run sends the same requests and prints the same output as 0.4.x.

- **Forms.** Any spelling Python's `ipaddress` accepts works, and cn sends the compressed
  lower-case form, so two spellings of one address are one lookup and one row. Rows show the
  address as the grid returns it: to join them to your own list, compare addresses, not text.
  `not_found` keeps each object as typed.
- **Refused before any lookup,** with the form to type instead: an IPv4-mapped address
  (`::ffff:10.20.0.5`: `IPv4-mapped IPv6 address; use 10.20.0.5`; also in Bulk DNS Lookup and
  `ping`) and a zone ID in `ip`, `subnet` and Bulk DNS Lookup (`2001:db8::5%eth0`: `Infoblox
  stores no zone ID (%eth0); use 2001:db8::5`). `ip` refuses `::`, `::1` and link-local addresses
  as reserved, as for IPv4.
- **Columns.** There is no family column; the address says which family a row is. IPv6 rows share
  each section and sheet with the IPv4 rows, and a field IPv6 lacks is an empty cell: `MAC`,
  `DHCP utilization %`, the range counts and `DHCP failover`. `DUID` (JSON `duid`) is the DHCPv6
  identity. It appears in `ip` and in the `fixed addresses` of `subnet` whenever the run looks up
  an IPv6 object, empty for an IPv4 row, and an IPv4-only run has none. Like `tcp_<port>`, it
  follows the input, not the data: read it with `.duid // ""`. DHCPv6 options are shown as
  returned, not decoded.
- **Unused addresses and PTR names.** `ip` shows a row for each IPv6 address for which the grid
  returns an object (whatever its status) and a `not_found` line `No matching IPv6 record found`
  when it returns none. `PTR name` comes from `record:ptr?ipv6addr=`, asked for each IPv6 address
  whose record types include `PTR`. These behaviours follow the WAPI reference and have not been
  compared with a live grid.
- **Containers.** An input shorter than /126 can be a container; the request counts are IPv4's.
  A container with more than 1,000 direct child networks fails with `more than 1,000 records
  match` (status 3), as in IPv4.
- **`ping`** expands an IPv6 prefix up to a /112, and with `--tcp` up to a /118. A name resolves to
  its IPv4 address first, and to an IPv6 address only when it has no IPv4 one. A link-local
  address needs its interface (`fe80::1%eth0`). `NO ROUTE` means that this host has no route to
  the address, or no IPv6: it is neither an answer nor a failure.
- **Bulk DNS Lookup** takes IPv6 addresses and prefixes up to a /112.

### Bulk ping (`cn ping`)

```bash
cn ping 10.1.2.3 web01.example.net
cn ping 10.1.2.0/28 --tcp 22,443 --format md
cn ping db01 --tcp 5432 && echo '5432 is open'
cn ping 2001:db8:20::5 --format md
```

Targets are IP addresses of either family, host names and networks (IPv4 up to a /16, IPv6 up to a
/112). A single address is pinged as given, `127.0.0.1` and `::1` too. Names are resolved once, to
an IPv4 address or, only when the name has none, to an IPv6 address, and ICMP and TCP use that
address; a name that does not resolve is listed in `not_found` as `no such host`. A link-local
IPv6 address needs its interface (`cn ping fe80::1%eth0`), and an IPv4-mapped one is refused with
the IPv4 address to use. `--tcp PORTS` also connects to up to 5 TCP ports (1-65535) and allows at
most 1,024 hosts (a /22, or an IPv6 /118). Every probe gives up after 3 seconds. ICMP runs the
system's `ping`: on Linux `ping -n -w3 -c2` for both families, so `ping` must take IPv6 literals
(current iputils does); on macOS `ping -n -c 2 -t 3`, and `ping6 -n -c 2` for IPv6 (it has no
deadline flag, so `cn` stops a ping still running after 7 seconds); on Windows `ping -n 2 -w 1500`. On
Windows cn counts the reply lines instead of reading Windows' summary, which is in the user's language,
so the answer is the same in every language.

Columns: `host`, `address`, `result` (`OK`, `OK (1/2 replies)`, `NO RESPONSE`, `NO ROUTE`, `ERROR`,
or `not run` when ICMP was skipped) and one `tcp_<port>` column per port: `open`, `closed` (refused
or reset; a firewall that rejects connections looks the same), `timeout`, `unreachable` or
`error`. `NO ROUTE` is an IPv6 ping from a Linux or macOS host that has no route to the address or
no IPv6; it is the ICMP side of `unreachable`, so a run in which nothing else answered exits 1, not
3. (On Windows the same case reads `NO RESPONSE`: the exit status is 1 either way.) The columns
follow the arguments: `--tcp 22,443` always gives `tcp_22` and `tcp_443`. Without a `ping` command
`cn ping` exits 2; with `--tcp` it skips ICMP and the ports decide the status.

### Configuration changes (`cn diff`)

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

### Health check (`cn doctor`)

```bash
cn doctor --format json | jq '.checks[] | select(.status == "error")'
```

`cn doctor` prints one row per check (`check`, `status`, `detail`), in a fixed order: Infoblox API,
Credentials, Infoblox WAPI, Site attribute, Network view, Config Repo, Active Dir, Cache, Theme.
Credentials, Infoblox WAPI, Site attribute and Network view are live checks: they run only when
Infoblox is configured, and they find the credential source, log in and read the WAPI version from
`<endpoint>?_schema`, check that `[site] ea_name` is defined on the grid and allowed on networks,
and list the network views and check the one the lookups search (`--view` or `[api] network_view`;
see [Network views](#network-views)). The Config Repo row is an `error` when none of the configured
repository directories can be read. `status` is `ok`, `warning`, `error`, `off` (not configured),
`info` or `skipped`. Nothing is changed, and it never prompts without a terminal. The Application
Setup status block in the menu shows the same rows without the live checks.

### Output

- stdout carries the result and nothing else; progress, warnings and errors go to stderr.
- Colour is off when stdout is not a terminal or `NO_COLOR` is set (`-t monochrome` does the same
  for the menu).
- `--format` is `table` (default), `json`, `md` or `csv` (one table, with `section` as the first
  column). `md` pipe tables do not render in Jira Data Center wiki markup or Teams chat; paste
  `table` output in a code block there.

### Exit status

| Status | Meaning | Examples |
| ------ | ------- | -------- |
| 0 | at least one object returned data | misses are listed in `not_found` |
| 1 | no object returned data | an IP outside every managed network |
| 2 | usage or configuration error | unknown command, no or invalid objects, MAC address, an IPv4-mapped or zoned IPv6 address, Infoblox not configured, a network view that is not on the grid, an empty `--view`, unreadable `--file`, no command and no terminal for the menu, an `[auth]` value that is not a variable name |
| 3 | incomplete or not saved | no credentials (TACACS, or Infoblox's own account) without a terminal, a GPG file for another user, authentication failure, timeout or server error, rejected or too-large query, the network views could not be listed while one was selected, report not written |
| 130 | interrupted | Ctrl-C |

Status 1 means "no record", not "the IP is free": an unused IPv4 address returns `UNUSED` with
status 0.
With status 3, stdout still holds what was found.

`ping`, `diff` and `doctor` use the same statuses with their own meaning of "data":

| Status | `cn ping` | `cn diff` | `cn doctor` |
| ------ | --------- | --------- | ----------- |
| 0 | a host answered ICMP; with `--tcp`, a port was `open` | at least one row in `changes` | no check failed (`warning`, `off`, `info` and `skipped` are allowed) |
| 1 | no host answered (`NO ROUTE` is no answer), or no port was open | no change in the window, or no such device or snapshot | never |
| 2 | no targets, a target that is not an IP address, network or name, an IPv4-mapped IPv6 address, a link-local address without an interface, more than a /16 (IPv6: a /112; 1,024 hosts with `--tcp`), bad `--tcp`, no `ping` command without `--tcp` | no devices, bad `--since` or `--line`, `-r FILE`, `[config_repo]` off | the endpoint serves no WAPI schema, `[site] ea_name` is not defined or not allowed on networks, `[api] network_view` (or `--view`) names no network view on the grid, no configuration repository directory can be read, an `[auth]` value that is not a variable name, `-r FILE` |
| 3 | a probe could not run (`ERROR`, `error`), report not written | a repository directory, history folder or snapshot could not be read | no credentials (TACACS, or Infoblox's own account) without a terminal, a GPG file for another user, login rejected, timeout or server error, the network views could not be listed while one is selected |

`--report` appends the result to the xlsx report (`[report] filename`, or `-r FILE`, which implies
`--report`); the command line does not save without it. A report that cannot be written makes the
status 3.

pandas and openpyxl load at the first save, not at start-up. If they cannot be loaded, the save
fails with a message that names the library and the `pip install -r requirements.txt` command for
the Python that runs `cn` (status 3 on the command line); lookups and `cn doctor` still work. A new
report is created with openpyxl on every machine, as every append already was. Before 0.4.1 a
machine that had xlsxwriter installed created it with that library instead, and URL-like text in
the first rows became a link; it is plain text now, as in every later row.

`requests` and `urllib3` load at the first Infoblox request, not at start-up, so `cn ping`,
`cn diff` and `cn doctor` without Infoblox never load them. If `requests` cannot be loaded, the
first Infoblox request ends the run with `cn: unexpected error. Check logs.` (status 3 on the
command line) and the log has the `ImportError`; reinstall the requirements.

### JSON for scripts

JSON keys are stable: section and column keys are lower-case snake_case (`ip_information`,
`dns_records`, `fqdn`, `location`, `subnets`, `ip_address`, `a_record`), a key never contains data,
and empty sections are kept. Keys are only ever added, never renamed or removed. Misses are
listed in `not_found` as `{object, reason}`, and `warnings` lists what was cut off or could not
be read.

| Command  | Sections |
| -------- | -------- |
| `subnet` | `subnets`, `child_containers`, the detail sections (`general`, `dhcp_range`, ...), `warnings`; the rows carry `network_view` |
| `ip`     | `ip_information`, `not_found`, `warnings` |
| `fqdn`   | `fqdn`, `not_found`, `warnings` |
| `site`   | `location`, `not_found`, `warnings` |
| `ping`   | `ping` (`host`, `address`, `result`, `tcp_<port>`...), `not_found` |
| `diff`   | `compared`, `changes`, `not_found`, `warnings` |
| `doctor` | `checks` |

New columns: `fqdn` has `type`, `canonical`, `dns_view`, `zone`, `ttl` and `ptr`; `ip_information`
has `network_view`, `ptr_name` and, in runs that look up an IPv6 object, `duid`; the
`fixed_addresses` of `subnet` have `duid` in the same runs; `subnets`, `general` and `location`
have `dhcp_utilization`;
`dhcp_range` has `utilization`, `utilization_status`, `leases`, `static` and `total`;
`child_containers` has `container`, `child_container`, `comment` and `utilization`. Utilization
values are numbers when known and `""` when not. `network_view` is in every row of
`ip_information`, `subnets`, `location`, the detail sections of `subnet`, `child_containers` and the
`warnings` of `subnet`, and `dns_view` in every row of `fqdn`, on every grid; an object held in
several views is a row for each. A `ping` `result` can be `NO ROUTE`. `duid` follows the input, not
the data, so read it with `.duid // ""` (jq) or `row.get("duid", "")` (Python).

```bash
set -o pipefail
cn subnet 10.1.2.0/24 --format json | jq -r '.dns_records[].a_record'
cn ip --file ips.txt --format json | jq -r '.not_found[].object'
cn ip 10.20.0.5 --format json | jq -r '.ip_information[] | "\(.network_view) \(.subnet)"'
cn ip 10.20.0.5 2001:db8:20::5 --format json | jq -r '.ip_information[] | "\(.ip) \(.duid // "")"'
cn ping web01 --tcp 443 --format json | jq -r '.ping[] | select(.tcp_443 == "open") | .host'
```

Use `set -o pipefail` so that a failed `cn` is not hidden by the status of `jq`.

### Credentials

`cn` logs in as `$USER` with `$TACACS_PW` (on Windows the user name is `%USERNAME%`, which is the
default of the `[auth]` setting `device_user_var`); if the password is not set, a GPG credentials
file younger than 24 hours is used (see GPG Credentials File below). Without a terminal `cn` never
prompts: it exits 3 at once with a message that names `TACACS_PW` and the GPG file, so cron jobs
and `ssh host cn …` cannot hang. `cn doctor` shows which source applies and whether the login
works. On Windows, set the password for one terminal as described under [Windows](#windows).

Infoblox can log in with an account of its own, for example a read-only service account, while
devices and Active Directory keep the TACACS login. Four settings give it: `INFOBLOX_USER` (the
user name; it wins over `[api] user`), `INFOBLOX_PW` (the password), `[api] user` in `.cn` (the user
name only: `.cn` holds no Infoblox password) and `[gpg] infoblox_credentials` (a GPG file, see
below). The password comes from `INFOBLOX_PW`, else the Infoblox GPG file, else a prompt; the user
name from `INFOBLOX_USER`, else `[api] user`, else the GPG file's `User =` line. `$USER` is never
used as the Infoblox user name.

Once any of them is set, Infoblox never uses the TACACS login: a missing half is asked for on a
terminal, and without one `cn` exits 3 and names it, with the reason when a GPG file could not be
used (`cn: no Infoblox password for svc-ipam: set INFOBLOX_PW, or [gpg] infoblox_credentials`). A
GPG file for a different user than `INFOBLOX_USER` or `[api] user` stops the run before anything is
sent. `[api] user` in `.cn` with `INFOBLOX_PW` exported is the setup to start with:

```ini
[api]
user = svc-ipam
```

```bash
read -rs -p 'Infoblox password: ' INFOBLOX_PW; echo; export INFOBLOX_PW
cn ip 10.20.0.5
```

The `.cn` keys apply to every `cn` run of that user, cron jobs included: once `[api] user` is set,
a job without `INFOBLOX_PW` or the GPG file exits 3. Give the job one of them, or keep it on the
TACACS login with `cn -c ~/.cn-tacacs …`, where `~/.cn-tacacs` sets to empty every Infoblox
setting your `~/.cn` has: `[api]` / `user =`, `[gpg]` / `infoblox_credentials =`, and `[auth]` /
`infoblox_user_var =` and `infoblox_password_var =` (empty means `INFOBLOX_USER` and `INFOBLOX_PW`,
which the job does not export). `-c` adds a layer on top of `~/.cn`, so the empty values override
it, while a file that merely lacks the keys would change nothing.

`cn` does not read `INFOBLOX_USERNAME` or `INFOBLOX_PASSWORD`, the names the Terraform provider and
the Ansible NIOS modules use, unless `[auth]` names them (below). An automation account exported
for those tools is never used by accident; `cn doctor` shows which login applies.

When the grid refuses the account's login, `cn` says so with the user and the source of the
password (`Infoblox refused user 'svc-ipam' (password from INFOBLOX_PW).`), sends an account's
first request alone and, after a refusal, nothing more as that account for the rest of the run: a
wrong password costs one refused login per run. A cron job still costs one per run, so act on exit
3 before the grid's lockout (if enabled) locks the account.

The names of the four variables are configurable in `[auth]`: `device_user_var` (default `USER`, and
`USERNAME` on Windows), `device_password_var` (`TACACS_PW`), `infoblox_user_var` (`INFOBLOX_USER`) and
`infoblox_password_var` (`INFOBLOX_PW`). The section holds names, never passwords. A blank value
means the default, and a value that is not a variable name stops the login with exit 2 and the
key's name. When `cn` says where a value came from, it names the variable (`password from
INFOBLOX_PASSWORD`). When it asks you to set a variable that is not set, it names the `[auth]` key
instead (`set the variable named in [auth] infoblox_password_var`): `cn` cannot tell a variable
name from a password typed there by mistake, so it prints a custom name only once that variable
exists. To use the account the Terraform provider and the Ansible NIOS modules read, say so in two
lines:

```ini
[auth]
infoblox_user_var = INFOBLOX_USERNAME
infoblox_password_var = INFOBLOX_PASSWORD
```

`cn` then logs in with whatever those tools use, write rights included (`cn` itself only reads).
The names are read when `cn` logs in: edit `.cn` and restart `cn`.

## Configuration

`cn-tool` reads ini-style configuration from these files, in this order (a later file overrides an
earlier one):

1. `.cn` in the root of a zip or a clone, next to `main.py` (a pip install has none)
2. `~/.cn` (`%USERPROFILE%\.cn` on Windows), the file `cn init` creates
3. a file passed with `-c`

Save `.cn` as UTF-8; a byte-order mark is fine. A file in another encoding (a Windows ANSI code page
with an accented letter in it) is not read: `cn` logs the parse error and runs on its defaults.
Paths may start with `~`, and on Windows may be drive paths such as `D:\configs`. The log, the
report, the cache and the GPG file default to `~/cn.log`, `~/report.xlsx`, `~/.cn-cache` and
`~/cn-tool.gpg`, in your home directory on every system; the keys below move them.

Example:

```ini
[api]
endpoint = https://infoblox.example.com
verify_ssl = true
timeout = 10
# Infoblox network view the lookups search (empty: every view; cn --view / --all-views override it)
# network_view = prod

[logging]
logfile = ~/cn.log
level = INFO

[report]
filename = ~/report.xlsx
auto_save = true

[config_repo]
directory = /opt/data/configs
excluded_dirs = old,history
history_dir = history

[cache]
enabled = true
directory = ~/.cn-cache

[theme]
theme = default
```

Optional sections (all keys may be omitted):

```ini
[ssh]
config_file = ~/.ssh/config
# device_name_filter = (sw|rtr|core)\d+   ; only query hosts whose reverse-DNS name matches

[site]
# code_pattern = ^[A-Za-z0-9]{3}(?:-[A-Za-z0-9]{1,4})?$   ; shape of a site code (default: any 2-64 char token)
# ea_name = Site                                          ; Infoblox extensible attribute that holds the site code (default: none)
# comment_pattern = ^[^;]+;\s*{site}\s*(;|$)              ; where the site appears in Infoblox subnet comments
# hostname_pattern = \b{country}{site_compact}[-_\w]*\b    ; how a site's device names look in configs
```

Site codes and device naming differ between organisations, so by default cn-tool accepts
any short token as a site code, matches it as a whole word anywhere in a subnet comment,
looks for devices whose names start with it, and queries every host you give it.

With `ea_name` set, a site code is looked up in that extensible attribute first (IPv4 and IPv6
networks), and subnet comments are searched only when no subnet carries it; the menu and
`cn site` then say so (`No subnet has the extensible attribute Site = DNS; matched DNS in subnet
comments instead.`). If the attribute query fails there is no fallback, so a wrong name is an
error that points to `cn doctor`. An attribute defined for IPv4 objects only gives the warning
`IPv6 subnets not searched: <reason>`. Keyword search (`-k`) never uses the attribute.

## Optional Integrations

### GPG Credentials File

To avoid interactive password prompts, you can store credentials in a
GPG-encrypted file and point `[gpg] credentials` or `-g/--gpg-file` at it.

The decrypted file must contain exactly these fields:

```text
User = your-username
Password = your-password
```

One way to create it is:

```bash
cat > /tmp/cn-tool-credentials.txt <<'EOF'
User = your-username
Password = your-password
EOF

gpg --encrypt --recipient YOUR_KEY_ID \
  --output ~/cn-tool.gpg \
  /tmp/cn-tool-credentials.txt

rm -f /tmp/cn-tool-credentials.txt
```

Notes:

- `cn-tool` will ignore credential files older than 24 hours.
- The file must be decryptable by `gpg` in the environment where `cn-tool` runs.
- The decrypted text must be UTF-8 (a byte-order mark at the start is dropped). On Windows, `gpg`
  comes from Gpg4win, and PowerShell 5.1's `>` writes UTF-16, which is not read: see
  [Windows](#windows).
- If you do not want to use GPG, set `TACACS_PW` or enter the credential interactively.

#### Infoblox account file

Infoblox's own account (see [Credentials](#credentials)) can have a file of its own: point
`[gpg] infoblox_credentials` at it. It has the same two lines (`User =` and `Password =`) but, unlike
the file above, no age limit; recreate it when the password changes. One way to create it, without
writing anything plain to disk:

```bash
read -rs -p 'Infoblox password: ' pw; echo
printf 'User = %s\nPassword = %s\n' svc-ipam "$pw" |
  gpg --yes --encrypt --recipient YOUR_KEY_ID --output ~/infoblox.gpg
unset pw
chmod 600 ~/infoblox.gpg
```

`printf` is a shell builtin, so the password never appears in the process list, and `--yes` lets the
same command replace the file when the password changes. A cron job decrypts with `gpg --batch`, so
it needs a key that gpg can use without asking: a passphrase cached in gpg-agent, or a key kept for
this purpose.

### Active Directory

```ini
[ad]
enabled = true
uri = ldap://your-ad-server.example.com
user = domain\user
search_base = CN=Subnets,CN=Sites,CN=Configuration,DC=example,DC=com
connect_on_startup = false
```

### Email

```ini
[email]
enabled = true
send_on_exit = false
to = some_user@example.com
server = smtp.example.com
port = 587
use_tls = true
use_auth = true
user = some_user@example.com
password = app-password-or-service-password
```

### SD-WAN YAML Search

```ini
[sdwan_yaml_search]
enabled = false
repository_paths = /path/to/repo1,/path/to/repo2
```

### Config Analyzer

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

## Notes

- Reports are written to `report.xlsx` in your home directory by default.
- The `Application Setup` menu edits the user-level `~/.cn` file and rewrites it without its
  comments: edit the file in a text editor to keep them.
- Secrets can be provided interactively or via your own local configuration.
