# Ping and monitoring

[Documentation](README.md) · [Project README](../README.md)

## Bulk ping (`cn ping`)

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

Columns: `host`, `address`, `result` (the ICMP result alone, whatever the ports did: `OK`,
`OK (1/2 replies)`, `NO RESPONSE`, `NO ROUTE`, `ERROR`,
or `not run` when ICMP was skipped) and one `tcp_<port>` column per port: `open`, `closed` (refused
or reset; a firewall that rejects connections looks the same), `timeout`, `unreachable` or
`error`. `NO ROUTE` is an IPv6 ping from a Linux or macOS host that has no route to the address or
no IPv6 (`ping` printed no counts and says `Network is unreachable`, `Address family not supported`
or, from macOS `ping6`, `No route to host`); it is the ICMP side of `unreachable`, so a run in which
nothing else answered exits 1, not 3. (On Windows the same case reads `NO RESPONSE`: the exit status
is 1 either way.) The columns follow the arguments: `--tcp 22,443` always gives `tcp_22` and
`tcp_443`. Without a `ping` command `cn ping` exits 2; with `--tcp` it skips ICMP and the ports
decide the status.

## Ping monitor (`cn monitor`)

```bash
cn monitor 10.1.2.0/24 --for 2h --every 1m        # watch for 2 hours, then print the summary
cn monitor 10.1.2.0/28 --every 30s                # until q or Ctrl+C
cn monitor --file sites.txt --tcp 22              # one round, recorded, with the earlier rounds
cn monitor --list                                 # the recorded requests, running ones included
cn monitor --show a3f9 --since 24h --format md    # a summary from the history; nothing is pinged
cn monitor --follow a3f9                          # the live view of a run another process records
cn monitor --rerun a3f9 --for 8h                  # a3f9's targets and ports again, its interval, 8 hours
cn monitor --runs a3f9                            # list the full run IDs for a request
cn monitor --delete-run RUN_ID                    # delete one run (asks first)
cn monitor --delete a3f9                          # delete a recorded request (asks first)
cn monitor --clear --yes                          # empty the history, without asking
```

`cn monitor` (menu item `m`, "Ping Monitor") pings `cn ping`'s targets, with the same limits and
`--tcp`, round after round, and records every round in the ping history. Its summary says which
hosts were seen, when first and last, in how many rounds, and when they stayed online
(`09:00–09:41, 09:55–now`, UTC). A crontab line that records one round every 5 minutes:

```
*/5 * * * * cn monitor --file sites.txt --since 0m --format json >/dev/null
```

- **How long.** Without `--every` and `--for` a run is one round. `--every INTERVAL` (`30s`, `5m`,
  `1h`; at least `10s`) starts a round every INTERVAL, until `q` or Ctrl+C unless `--for DURATION`
  (`30m`, `2h`, `1d`) ends it; `--for` alone pings every minute. Rounds start on a grid of slots
  (the start plus a whole number of intervals): a round that overruns skips the slots it covered,
  and the next round starts at the next slot, never right after the late one. Names are resolved
  again in every round.
- **Earlier rounds.** The summary adds the rounds of the same request that the history already
  holds, so a second run continues the record. `--since WHEN` (`24h`, `7d`, `2026-10-01`, UTC)
  keeps the earlier rounds from WHEN on; `--since 0m` takes this run's rounds only. The same request
  means the same targets, normalised and sorted (`10.1.2.5/24` is `10.1.2.0/24`, a name is lower
  case, order and duplicates do not matter), the same TCP ports and the same expanded host list. An
  edited `--file` is a new request, and so are the same targets with other ports.
- **The live view.** While a run goes on, and stderr is a terminal, every address of a small
  network is one character, one block per subnet and a `Hosts` block for single addresses and
  names; when they do not fit the terminal, one counter line per target replaces them. A host that
  comes or goes prints a change line above the view.

  | Character | Meaning |
  | --------- | ------- |
  | `!` | replied (in the warning colour when only some echo requests did) |
  | `R` | rejected: the host itself sent an ICMP error, so it is up, behind its own firewall |
  | `T` | silent to ping, but a TCP port answered (only with `--tcp`) |
  | `x` | gone: not seen now, but seen earlier in the window |
  | `U` | unreachable: never seen, and an ICMP error came from another address (a router, a firewall, this host), or IPv6 `NO ROUTE`; it stays until the host is seen |
  | `E`, `?` | the probe failed; the name did not resolve |
  | `.` | silent: no answer (a firewall that drops looks the same) |

- **The table** (`v`) has a row for each host seen so far: `Host`, `Flag` (its character in the
  grid, in the grid's colour; the legend under the table lists the flags that its rows show),
  `Latest ping`, one `TCP <port>` column for each `--tcp` port (the port's state in the latest
  round: `open`, `closed`, `timeout`, `unreachable` or `error`; empty for a host that was not seen
  in it), `Last seen` and `Seen`. `Latest ping` is the ICMP result alone: `OK` means the echo
  requests were answered, whatever the ports did, so a host can be `OK` and have a `closed` port,
  and a `T` host reads `NO RESPONSE` with its open port beside it. A narrow terminal drops the
  columns `Last seen`, `Seen` and the ports (the last first), in that order.
- **Keys**, read only when stdin is a terminal: `q` or the first Ctrl+C ends the run, drops the
  round in flight and prints the summary of the finished rounds; a second Ctrl+C stops at once
  (exit 130 on the command line); `v` switches between the grid and the table. On Linux and macOS,
  SIGTERM and SIGHUP end a run as `q` does. Without a terminal (cron), or in the background
  (`cn monitor ... &`, or Ctrl+Z and `bg`), nothing is drawn and no key is read, and stdout gets
  only the result.
- **`REJECTED` and `UNREACHABLE`**, read by the monitor only: when `cn ping` reads `NO RESPONSE`,
  the monitor looks for an ICMP error in the ping's output, and its sender decides: the pinged
  address is `REJECTED`, any other address (or, on macOS, a local send error) `UNREACHABLE`. A
  reply always wins, and a line that cannot be placed stays `NO RESPONSE`. Windows prints an IPv6
  ICMP error without its sender, so an IPv6 target there is only ever `!` or `.`. `cn ping` is
  unchanged.
- **`--list`** lists the recorded requests, newest first: `ID` (8 hex digits, the same in every
  run), `Targets` (the newest run's `--file` name, then the targets), `TCP`, `Runs`, `Rounds`,
  `Last round` and `State`: `running: round 14 of up to 120, next at 09:15:00`, `finished`,
  `stopped early`, `failed`, or `lost at 09:14:00` (the process ended without saying so: killed, a
  reboot, a closed console on Windows; a run is lost when it has given no sign of life for 2.5
  intervals or 60 seconds, whichever is longer, or its process on this machine is gone).
  **`--show ID`** prints a recorded request's summary from the history; `ID` may be a prefix of at
  least 4 hex digits that only one request starts with. **`--follow ID`** draws the live view of a
  run that another process records, until it ends or `q`, then prints the summary (at once, with a
  note on stderr, when nothing records the request); it needs a terminal on stderr. **`--rerun ID`**
  runs a recorded request again: its stored targets and TCP ports (a `--file` is not read again),
  with the interval and length of its newest run that pinged round after round (one round if none
  did); `--every` and `--for` change them, each alone. On a terminal one line says what is reused. A
  request with a run going on is refused (exit 2), so a crontab line such as `0 8 * * 1-5 cn monitor
  --rerun a3f9 --for 8h --format json > /var/tmp/a3f9.json` never starts a second run. An override
  sticks: the run a rerun starts is the newest run that pinged round after round, so it is the next
  template, and `--rerun ID --for 8h` makes a later plain `--rerun ID` run for 8 hours too (the
  one-round runs that cron feeds never replace it). **`--runs ID`** lists the full run IDs for a
  request; **`--delete-run RUN_ID`** removes one exact run and its rounds, preserving other runs of
  the request. If deletion exceeds its SQLite execution budget, it rolls back and leaves the run
  intact; stop other monitors and use `cn-mon --delete-run RUN_ID` for an oversized run.
  **`--delete ID`** deletes one recorded request, a
  row of `--list`, with every run, round and result of it, and **`--clear`** deletes every request.
  All three ask first (`... Delete it from <file>? This cannot be undone. [y/N]`): only `y` or `yes`
  deletes, anything else leaves the history alone (exit 1). Without a terminal they exit 2 and say so;
  `--yes` (`-y`) deletes without asking, and goes with `--delete-run`, `--delete` or `--clear` only.
  Deletion is refused (exit 2) if a selected run is active or its owner cannot be verified. A stale
  heartbeat alone does not establish that a local or remote process has stopped.
  None creates the history file, and `--clear` gives the space back but keeps the file (`--list`
  then exits 1).
- **The menu.** Item `m` opens at the list of recorded requests (at the target prompt when nothing
  is recorded). A number shows that request's summary, where a window (`24h`, `2026-10-08`) narrows
  it, `g` draws the grid of the last round, `f` follows the run going on, `n` starts a new run of the
  same targets, `r` runs the request again with the plan its keys line names, asking nothing, and `d`
  deletes the request after the `--delete` question (`r` and `d` are offered while no run of it goes
  on). At the list, `c` clears the history after the `--clear` question. A new run asks item 6's
  questions, whether to include the earlier rounds, then `Run for how long` (Enter: one round) and
  `Ping every` (Enter: 1m). With `[report] auto_save` the "Ping Monitor" sheet gets every host seen,
  with every online period.
- **The history** is an SQLite file, `[ping] history_file` (default `~/.cn-ping-history.db`), kept
  for `[ping] history_days` (default 30) days. It is one file per machine: SQLite's WAL journal does
  not work over a network file system, so a home directory on NFS or SMB works for one machine at a
  time. `--list`, `--show`, `--follow`, `--rerun` (before its run) and the menu's list never create or
  change it. Only a run (and its prune), `--delete`, `--clear` and the menu's `d` and `c` write, and
  the last four never create the file. A killed run keeps every round it finished and shows as
  `lost`. A history that cannot be written is reported once (`cn: monitor: history: ...`) and the run
  goes on without it, with exit status 3; so does a Python built without `sqlite3`.
