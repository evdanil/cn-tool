# Command line

[Documentation](README.md) · [Project README](../README.md)

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
| `subnet` | `10.1.2.0/24`, `10.1.2.0/255.255.255.0`, `2001:db8:20::/64` or an IP address (its subnet); a container prefix expands to its subnets and lists its child containers, not expanded | subnet summary with DHCP utilization %, DHCP ranges, DNS records, fixed addresses, every used IP address with its record types (`HOST`, `A`, `PTR`, `FA`, `RESERVATION`, `LEASE`, ...), extensible attributes (an IPv6 subnet has no DHCP utilization or failover); a `child containers` table for a container prefix; one summary row and one set of details per network view that holds the subnet |
| `ip`     | IPv4 and IPv6 addresses | network view (on a grid with several), subnet, DNS name, status, MAC (IPv4), DUID (IPv6) and PTR name, one row per network view that holds the address; an unused IPv4 address is reported as `UNUSED`; an address that no Infoblox network contains is in `not_found` as `No Infoblox network contains this address` |
| `fqdn`   | names or name prefixes (at least three characters) | A, AAAA, host and CNAME records whose name contains the text, with type, DNS view (on a grid with several), zone, TTL and a PTR check |
| `site`   | site codes; with `-k/--keyword`, keywords | the subnets of each site code, or matching each keyword, with DHCP utilization % and, on a grid with several network views, the network view |
| `ping`   | IPv4 and IPv6 addresses, host names, `10.1.2.0/24` and `2001:db8::/120` networks | ICMP result per host and, with `--tcp 22,443`, the state of each port |
| `monitor` | as `ping`; none with `--list`, `--show ID`, `--follow ID`, `--rerun ID`, `--delete ID` or `--clear` | pings round after round (`--every`, `--for`) and records each round in the ping history; then the hosts seen in the window (first and last seen, rounds seen, online periods), every host's result in the last round and a summary. `--list`: the recorded requests; `--show`, `--follow`: a recorded request's summary, from the history; `--rerun`: a new run of a recorded request, output as a run; `--delete`, `--clear`: one row per request deleted from the history, after asking |
| `diff`   | device names, as in `<name>.cfg` in the configuration repositories | configuration lines added or removed since the last change or `--since`, with the snapshot, author and time |
| `doctor` | none | one row per configuration, credential and Infoblox check |
| `init`   | none | nothing on stdout: it writes a commented starting configuration to `~/.cn` and never overwrites a file (exit 0 written, 2 the file exists, 3 it could not be written) |

`site` results are paged: up to 10,000 subnets per address family (IPv4 and IPv6 networks are
fetched separately); at the cap a warning says so. `fqdn` pages each record type (A, AAAA, host,
CNAME) and its PTR search up to 10,000 rows.

`ip`, `subnet`, `fqdn`, `site` and `doctor` add `--view NAME` and `--all-views` (see
[Network views](infoblox.md#network-views)). `ping` adds `--tcp PORTS`; `monitor` adds `--tcp PORTS`,
`--every INTERVAL`, `--for DURATION`, `--since WHEN`, `--list`, `--show ID`, `--follow ID`,
`--rerun ID`, `--delete ID`, `--clear` and `-y/--yes`; and `diff` adds `--since WHEN` and
`--line TEXT`. `doctor` and `init` take neither objects nor `--file`, and `monitor` takes no objects
with `--list`, `--show`, `--follow`, `--rerun`, `--delete` or `--clear`. `diff`, `doctor` and `init`
write no report: they have no `--report`, and `-r FILE` is refused with exit 2. An option name is
never abbreviated (`--rep` is an error, not `--report`).

Objects are arguments, or one per line from `--file PATH`; a positional `-` or `--file -` reads
standard input (in PowerShell use `--file`: it reserves `<`, so `cn subnet - < scope.txt` is not
possible there). Blank lines and `#` comments are ignored. Global options (`-c`, `-nc`, `-t`, `-l`,
`-r`, `-g`, `--log-level`) work before and after the command. `cn <command> --help` shows the
details of one command.

When stdin is a terminal, `cn ip -` waits for you to type the objects, and says so first on stderr:
`cn: reading objects from standard input; end with Ctrl-D on a line of its own.` On Windows the line
names `Ctrl-Z, then Enter` instead. A pipe or a redirected file gets no such line. Ctrl-C while you
type ends the run with `cn: interrupted` and exit status 130, without a traceback.

A command loads only the libraries it uses: pandas and openpyxl when it saves a report, netmiko
(with paramiko) when it queries a device over SSH, ldap3 when Active Directory connects, yaml for
the SD-WAN YAML search and diskcache for the cache. On a shared dev host (2 cores, load 2-3)
`cn --help` starts in about 0.15 s and `cn ip` reaches its credentials check in about 0.28 s;
before 0.4.1 they took about 0.5 s and 0.9 s. The menu starts faster for the same reason.

A bare object is routed by its shape: `cn 10.1.2.3` or `cn 2001:db8::5` runs `ip`, `cn 10.0.0.0/24`
or `cn 2001:db8:20::/64` runs `subnet`, `cn host.example.com` runs `fqdn`. Only an IPv4 or IPv6
address, a network of either family or an FQDN is recognised, and the two families mix inside one
kind (`cn 10.1.2.3 2001:db8::5` is `ip`). A MAC address, a partial address such as `10.1.2`, a
bracketed address (`[2001:db8::1]`) and a mix of kinds exit 2. `ping`, `monitor`, `diff` and
`doctor` are never inferred: use `cn ping 10.1.2.3 --tcp 443`.

## Health check (`cn doctor`)

```bash
cn doctor --format json | jq '.checks[] | select(.status == "error")'
```

`cn doctor` prints one row per check (`check`, `status`, `detail`), in a fixed order: Infoblox API,
Credentials, Infoblox WAPI, Site attribute, Network view, Config Repo, Active Dir, Cache, Theme.
Credentials, Infoblox WAPI, Site attribute and Network view are live checks: they run only when
Infoblox is configured, and they find the credential source, log in and read the WAPI version from
`<endpoint>?_schema`, check that `[site] ea_name` is defined on the grid and allowed on networks,
and list the network views and check the one the lookups search (`--view` or `[api] network_view`;
see [Network views](infoblox.md#network-views)). The Config Repo row is an `error` when none of the configured
repository directories can be read. `status` is `ok`, `warning`, `error`, `off` (not configured),
`info` or `skipped`. Nothing is changed, and it never prompts without a terminal. The Application
Setup status block in the menu shows the same rows without the live checks.

## Output

- stdout carries the result and nothing else; progress, warnings and errors go to stderr.
- Colour is off when stdout is not a terminal or `NO_COLOR` is set (`-t monochrome` does the same
  for the menu).
- `--format` is `table` (default), `json`, `md` or `csv` (one table, with `section` as the first
  column). `md` pipe tables do not render in Jira Data Center wiki markup or Teams chat; paste
  `table` output in a code block there.

## Exit status

| Status | Meaning | Examples |
| ------ | ------- | -------- |
| 0 | at least one object returned data | misses are listed in `not_found` |
| 1 | no object returned data | an IP outside every managed network |
| 2 | usage or configuration error | unknown command, no or invalid objects, MAC address, an IPv4-mapped or zoned IPv6 address, Infoblox not configured, a network view that is not on the grid, an empty `--view`, unreadable `--file`, no command and no terminal for the menu, an `[auth]` value that is not a variable name |
| 3 | incomplete or not saved | no credentials (TACACS, or Infoblox's own account) without a terminal, a GPG file for another user, authentication failure, timeout or server error, rejected or too-large query, the network views could not be listed while one was selected, report not written |
| 130 | interrupted | Ctrl-C |

Status 1 means "no record", not "the IP is free": an unused IPv4 address returns `UNUSED` with
status 0. An address that no Infoblox network contains is a miss, not a failure: the grid answers
HTTP 400 ("A network was not found for this address."), which cn lists in `not_found` as `No
Infoblox network contains this address`. It does not fail the run (status 1 when nothing else was
found, and no error in the log). Any other 400 is still a rejected query, status 3.
With status 3, stdout still holds what was found.

`ping`, `diff` and `doctor` use the same statuses with their own meaning of "data":

| Status | `cn ping` | `cn diff` | `cn doctor` |
| ------ | --------- | --------- | ----------- |
| 0 | a host answered ICMP; with `--tcp`, a port was `open` | at least one row in `changes` | no check failed (`warning`, `off`, `info` and `skipped` are allowed) |
| 1 | no host answered (`NO ROUTE` is no answer), or no port was open | no change in the window, or no such device or snapshot | never |
| 2 | no targets, a target that is not an IP address, network or name, an IPv4-mapped IPv6 address, a link-local address without an interface, more than a /16 (IPv6: a /112; 1,024 hosts with `--tcp`), bad `--tcp`, no `ping` command without `--tcp` | no devices, bad `--since` or `--line`, `-r FILE`, `[config_repo]` off | the endpoint serves no WAPI schema, `[site] ea_name` is not defined or not allowed on networks, `[api] network_view` (or `--view`) names no network view on the grid, no configuration repository directory can be read, an `[auth]` value that is not a variable name, `-r FILE` |
| 3 | a probe could not run (`ERROR`, `error`), report not written | a repository directory, history folder or snapshot could not be read | no credentials (TACACS, or Infoblox's own account) without a terminal, a GPG file for another user, login rejected, timeout or server error, the network views could not be listed while one is selected |

`cn monitor` decides by mode ("the window" is this run's rounds and the earlier ones `--since`
keeps):

| Status | A run (targets, `--rerun`) | `--list` | `--show`, `--follow` | `--delete ID`, `--clear` |
| ------ | -------------------------- | -------- | -------------------- | ------------------------ |
| 0 | a host was seen in the window; with `--tcp`, a port was `open` in some round | a request is recorded | a host was seen in the window; with TCP ports, a port was `open` | the request (`--clear`: every request) was deleted; or (`--clear`) the leftovers of an interrupted delete were freed |
| 1 | no host was seen, or no round finished | nothing is recorded | no host was seen in the window | nothing was deleted: the answer was not `y`, or (`--clear`) nothing is recorded, leftover rounds included |
| 2 | as `cn ping`, and `--every` under `10s`, `--for` shorter than `--every`, a bad interval, or two modes together; with `--rerun`: no request has that ID, a run of it is going on, targets or `--tcp` given, a `--for` shorter than the interval it keeps or an `--every` longer than the length it keeps | `--since`, targets or another mode given | no request has that ID, or the prefix starts several; `--follow` without a terminal on stderr | no request has that ID (nothing recorded included), the prefix starts several IDs or has fewer than 4 hex digits; a run of the request (`--clear`: any run) is going on; no terminal to ask on and no `--yes`; targets, `--tcp`, `--every`, `--for`, `--since` or another mode given; `--yes` without `--delete` or `--clear` |
| 3 | a probe could not run in a round of this run; the history could not be read or written (the summary is still printed); report not written; with `--rerun`: the history cannot be read (nothing started) | the history cannot be read | the history cannot be read; report not written | the history cannot be opened, read or written; nothing was deleted |
| 130 | a second Ctrl+C (the first ends the run with its summary) | Ctrl-C | Ctrl-C; with `--follow`, a second Ctrl+C | Ctrl-C (at the question: nothing was deleted) |

`--report` appends the result to the xlsx report (`[report] filename`, or `-r FILE`, which implies
`--report`); the command line does not save without it. A report that cannot be written makes the
status 3. `cn ping` writes the "Bulk PING" sheet, and `cn monitor` (a run, `--rerun`, `--show` or `--follow`)
the "Ping Monitor" sheet: every host seen in the window, with every online period.

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

## JSON for scripts

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
| `monitor` | a run or `--rerun`: `seen`, `latest`, `summary`, `not_found`; `--list`: `requests`; `--show` and `--follow`: `seen`, `latest`, `summary`; `--delete` and `--clear`: `deleted` (one row per request deleted) |
| `diff`   | `compared`, `changes`, `not_found`, `warnings` |
| `doctor` | `checks` |

`cn monitor`'s columns:

| Section | Columns |
| ------- | ------- |
| `seen` | one row per host seen in the window: `host`, `address`, `latest` (the ping result in the last finished round, never a port's answer: `cn ping`'s values plus `REJECTED` and `UNREACHABLE`), `tcp_<port>` (ports in ascending order), `first_seen`, `last_seen`, `seen_rounds`, `rounds` (integers), `online` (a list of `{"from", "to"}` times, `to` `null` while a period is open in a running request) |
| `latest` | every host of the last finished round: `host`, `address`, `result`, `tcp_<port>`; read from the history, a host that was not seen has an empty `address` |
| `summary` | `id`, `started`, `ended`, `rounds`, `earlier_rounds`, `interval` (seconds, `null` for one round), `hosts`, `seen`, `answering` |
| `requests` | `id`, `targets`, `tcp` (`-` for none), `runs`, `rounds`, `last_round`, `state` (`running`, `finished`, `stopped`, `failed` or `lost`), `detail` (the rest of the state, e.g. `round 14 of up to 120, next at 09:15:00`) |

Times are UTC, to the second (`2026-10-09T09:14:00+00:00`).

New columns: `fqdn` has `type`, `canonical`, `dns_view`, `zone`, `ttl` and `ptr`; `ip_information`
has `network_view`, `ptr_name` and, in runs that look up an IPv6 object, `duid`; the
`fixed_addresses` and `ip_addresses` of `subnet` have `duid` in the same runs; `ip_addresses`
(every used address of the subnet) has `ip_address`, `types`, `usage`, `names`, `lease_state` and
`mac` (IPv4 rows); `subnets`, `general` and `location` have `dhcp_utilization`;
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
cn monitor --show a3f9 --since 24h --format json | jq -r '.seen[] | "\(.host) \(.seen_rounds)/\(.rounds) \(.last_seen)"'
```

Use `set -o pipefail` so that a failed `cn` is not hidden by the status of `jq`.
