# cn-tool

`cn-tool` is a modular network utility for Infoblox lookups, bulk network
checks, configuration repository searches, and device inventory collection.

## What's new in 0.4.1

Faster start. A command loads only the libraries it uses: pandas and openpyxl when it saves a
report, netmiko when it queries a device, ldap3 when Active Directory connects. On a shared dev host
`cn --help` took 0.53 s and now takes 0.15 s, and `cn ip` reached its credentials check in 0.87 s
and now does it in 0.28 s. Two report changes come with it: a new report is always created with
openpyxl, and Bulk Trace saves now take the report lock like every other save. The details are in
the release notes of 0.4.1 on the Releases page of this repository. Version 0.4.0 added Infoblox
network views, and version 0.3.0 the command line, `cn diff`, `cn doctor` and Config Analyzer
0.2.0; their notes are on the same page.

## Included Features

- IP, subnet, FQDN, and location lookups using the Infoblox API; a site is found by an Infoblox
  extensible attribute (`[site] ea_name`) or by subnet comment; an object held in several network
  views is listed once per view, and `--view NAME` limits a lookup to one
- Command line (`cn subnet|ip|fqdn|site|ping|diff|doctor`) with table, JSON, Markdown and CSV
  output and exit codes for scripts
- Bulk ping with an optional TCP port check, resolve, and traceroute operations
- `cn diff`: which snapshot of a device added or removed a configuration line, and who made it
- `cn doctor`: configuration, credential and Infoblox WAPI checks
- Configuration repository search with optional SD-WAN YAML enrichment
- Device inventory queries in parallel (Cisco IOS/IOS-XE and NX-OS, platform autodetected)
- Config repository browser TUI (`python -m config_analyzer`)
- Active Directory subnet enrichment
- Excel report generation and optional email delivery
- Disk-backed cache for faster repeated lookups

## Installation

1. Clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Copy the sample configuration and adjust it for your environment:

```bash
cp .cn ~/.cn
```

5. Run the tool:

```bash
python main.py
```

On a shared server where users cannot write to the install directory, run
`python -m compileall -q /path/to/cn-tool` after each install or update, with the Python that runs
`cn`. Python cannot cache compiled modules in a read-only directory, so without this step it
compiles every cn module on every start: about 0.14 s more for a lookup (0.42 s instead of 0.28 s
on a shared dev host).

## Command line

`cn <command>` runs one lookup without the menu, prints the result on stdout and exits with a
status a script can test. Without a command the menu opens as before.

```
cn [global options] <command> [objects…|-] [--file PATH|-] [--format table|json|md|csv] [--report]
```

For scripted use, install a symlink instead of calling `python main.py`: a shell alias is not
expanded in scripts, cron jobs or `ssh host cmd`. Native Windows is not supported.

```bash
ln -s /path/to/main.py ~/bin/cn
```

| Command  | Objects | Returns |
| -------- | ------- | ------- |
| `subnet` | `10.1.2.0/24`, `10.1.2.0/255.255.255.0` or an IP address (its subnet); a container prefix expands to its subnets and lists its child containers, not expanded | subnet summary with DHCP utilization %, DHCP ranges, DNS records, fixed addresses, extensible attributes; a `child containers` table for a container prefix; one summary row and one set of details per network view that holds the subnet |
| `ip`     | IPv4 addresses | network view (on a grid with several), subnet, DNS name, status, MAC and PTR name, one row per network view that holds the address; an unused address is reported as `UNUSED` |
| `fqdn`   | names or name prefixes (at least three characters) | A, AAAA, host and CNAME records whose name contains the text, with type, DNS view (on a grid with several), zone, TTL and a PTR check |
| `site`   | site codes; with `-k/--keyword`, keywords | the subnets of each site code, or matching each keyword, with DHCP utilization % and, on a grid with several network views, the network view |
| `ping`   | IPv4 addresses, host names, `10.1.2.0/24` networks | ICMP result per host and, with `--tcp 22,443`, the state of each port |
| `diff`   | device names, as in `<name>.cfg` in the configuration repositories | configuration lines added or removed since the last change or `--since`, with the snapshot, author and time |
| `doctor` | none | one row per configuration, credential and Infoblox check |

`site` results are paged: up to 10,000 subnets per address family (IPv4 and IPv6 networks are
fetched separately); at the cap a warning says so. `fqdn` pages each record type (A, AAAA, host,
CNAME) and its PTR search up to 10,000 rows.

`ip`, `subnet`, `fqdn`, `site` and `doctor` add `--view NAME` and `--all-views` (see
[Network views](#network-views)). `ping` adds `--tcp PORTS`, and `diff` adds `--since WHEN` and
`--line TEXT`. `doctor` takes neither objects nor `--file`. `diff` and `doctor` write no report:
they have no `--report`, and `-r FILE` is refused with exit 2. An option name is never abbreviated
(`--rep` is an error, not `--report`).

Objects are arguments, or one per line from `--file PATH`; a positional `-` or `--file -` reads
standard input. Blank lines and `#` comments are ignored. Global options (`-c`, `-nc`, `-t`, `-l`,
`-r`, `-g`, `--log-level`) work before and after the command. `cn <command> --help` shows the
details of one command.

A command loads only the libraries it uses: pandas and openpyxl when it saves a report, netmiko
(with paramiko) when it queries a device over SSH, ldap3 when Active Directory connects, yaml for
the SD-WAN YAML search and diskcache for the cache. On a shared dev host (2 cores, load 2-3)
`cn --help` starts in about 0.15 s and `cn ip` reaches its credentials check in about 0.28 s;
before 0.4.1 they took about 0.5 s and 0.9 s. The menu starts faster for the same reason.

A bare object is routed by its shape: `cn 10.1.2.3` runs `ip`, `cn 10.0.0.0/24` runs `subnet`,
`cn host.example.com` runs `fqdn`. Only a CIDR network, an IPv4 address or an FQDN is recognised;
a MAC address, an IPv6 address, a partial address such as `10.1.2` and a mix of kinds exit 2.
`ping`, `diff` and `doctor` are never inferred: use `cn ping 10.1.2.3 --tcp 443`.

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
An input shorter than /30 also lists its child containers (`container`, `child container`,
`comment`, `utilization %`); they are not expanded, so query one to see its subnets.

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

### Bulk ping (`cn ping`)

```bash
cn ping 10.1.2.3 web01.example.net
cn ping 10.1.2.0/28 --tcp 22,443 --format md
cn ping db01 --tcp 5432 && echo '5432 is open'
```

Targets are IPv4 addresses, host names and IPv4 networks (at most a /16). A single address is
pinged as given, `127.0.0.1` too. Names are resolved once to IPv4, and ICMP and TCP use that
address; a name that does not resolve is listed in `not_found` as `no such host`. `--tcp PORTS`
also connects to up to 5 TCP ports (1-65535) and allows at most 1,024 hosts (a /22). Every probe
gives up after 3 seconds.

Columns: `host`, `address`, `result` (`OK`, `OK (1/2 replies)`, `NO RESPONSE`, `ERROR`, or `not run`
when ICMP was skipped) and one `tcp_<port>` column per port: `open`, `closed` (refused or reset;
a firewall that rejects connections looks the same), `timeout`, `unreachable` or `error`. The
columns follow the arguments: `--tcp 22,443` always gives `tcp_22` and `tcp_443`. Without a
`ping` command `cn ping` exits 2; with `--tcp` it skips ICMP and the ports decide the status.

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
| 2 | usage or configuration error | unknown command, no or invalid objects, MAC or IPv6 address, Infoblox not configured, a network view that is not on the grid, an empty `--view`, unreadable `--file`, no command and no terminal for the menu |
| 3 | incomplete or not saved | no credentials without a terminal, authentication failure, timeout or server error, rejected or too-large query, the network views could not be listed while one was selected, report not written |
| 130 | interrupted | Ctrl-C |

Status 1 means "no record", not "the IP is free": an unused IP returns `UNUSED` with status 0.
With status 3, stdout still holds what was found.

`ping`, `diff` and `doctor` use the same statuses with their own meaning of "data":

| Status | `cn ping` | `cn diff` | `cn doctor` |
| ------ | --------- | --------- | ----------- |
| 0 | a host answered ICMP; with `--tcp`, a port was `open` | at least one row in `changes` | no check failed (`warning`, `off`, `info` and `skipped` are allowed) |
| 1 | no host answered, or no port was open | no change in the window, or no such device or snapshot | never |
| 2 | no targets, a target that is not an IPv4 address, network or name, IPv6, more than a /16 (1,024 hosts with `--tcp`), bad `--tcp`, no `ping` command without `--tcp` | no devices, bad `--since` or `--line`, `-r FILE`, `[config_repo]` off | the endpoint serves no WAPI schema, `[site] ea_name` is not defined or not allowed on networks, `[api] network_view` (or `--view`) names no network view on the grid, no configuration repository directory can be read, `-r FILE` |
| 3 | a probe could not run (`ERROR`, `error`), report not written | a repository directory, history folder or snapshot could not be read | no credentials without a terminal, login rejected, timeout or server error, the network views could not be listed while one is selected |

`--report` appends the result to the xlsx report (`[report] filename`, or `-r FILE`, which implies
`--report`); the command line does not save without it. A report that cannot be written makes the
status 3.

pandas and openpyxl load at the first save, not at start-up. If they cannot be loaded, the save
fails with a message that names the library and the `pip install -r requirements.txt` command for
the Python that runs `cn` (status 3 on the command line); lookups and `cn doctor` still work. A new
report is created with openpyxl on every machine, as every append already was. Before 0.4.1 a
machine that had xlsxwriter installed created it with that library instead, and URL-like text in
the first rows became a link; it is plain text now, as in every later row.

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
has `network_view` and `ptr_name`; `subnets`, `general` and `location` have `dhcp_utilization`;
`dhcp_range` has `utilization`, `utilization_status`, `leases`, `static` and `total`;
`child_containers` has `container`, `child_container`, `comment` and `utilization`. Utilization
values are numbers when known and `""` when not. `network_view` is in every row of
`ip_information`, `subnets`, `location`, the detail sections of `subnet`, `child_containers` and the
`warnings` of `subnet`, and `dns_view` in every row of `fqdn`, on every grid; an object held in
several views is a row for each.

```bash
set -o pipefail
cn subnet 10.1.2.0/24 --format json | jq -r '.dns_records[].a_record'
cn ip --file ips.txt --format json | jq -r '.not_found[].object'
cn ip 10.20.0.5 --format json | jq -r '.ip_information[] | "\(.network_view) \(.subnet)"'
cn ping web01 --tcp 443 --format json | jq -r '.ping[] | select(.tcp_443 == "open") | .host'
```

Use `set -o pipefail` so that a failed `cn` is not hidden by the status of `jq`.

### Credentials

`cn` logs in as `$USER` with `$TACACS_PW`; if it is not set, a GPG credentials file younger than
24 hours is used (see GPG Credentials File below). Without a terminal `cn` never prompts: it exits
3 at once with a message that names `TACACS_PW` and the GPG file, so cron jobs and
`ssh host cn …` cannot hang. `cn doctor` shows which source applies and whether the login works.

## Configuration

`cn-tool` reads ini-style configuration from:

1. `.cn` next to the script
2. `~/.cn`
3. a file passed with `-c`

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
- If you do not want to use GPG, set `TACACS_PW` or enter the credential interactively.

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

- Reports are written to `report.xlsx` by default.
- The `Application Setup` menu edits the user-level `~/.cn` file.
- Secrets can be provided interactively or via your own local configuration.
