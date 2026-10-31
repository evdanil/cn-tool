# Infoblox lookup reference

[Documentation](README.md) · [Project README](../README.md)

## PTR, DHCP utilization and child containers

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

## Network views

A network view is an Infoblox partition of the IP space: the same network, address or name can
exist in several views, each with its own data. A grid with one view has nothing to choose, and
nothing changes there.

By default `ip`, `subnet`, `fqdn` and `site` search every network view and list one row per view
that holds the object. Searches by network or record name can span views in one request.
Address-keyed searches and requests for a network's objects need an explicit view to avoid
default-view-only answers. On a grid with several views, cn repeats those requests for each
applicable view and joins the results. Choose one view instead with:

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

- **`ip`**: one row per address and network view. Address and applicable PTR requests use the
  same view scope, and PTR results stay with that view's row. A record from another view does
  not populate a row for the selected view.
- **`subnet`**: five requests per network on a grid with one view, and `1 + 4k` on a grid with k
  views (the network lookup once, the DNS records, ranges, fixed addresses and used IP addresses
  once for each view). The answers are split by view into one summary row and one set of details per
  view. The 10,000-row cap of a list is per view and per list, and the warning says which list was
  cut. The menu names the view (`Details [2/2] for: 10.20.0.0/24 in network view lab`), and the "Subnet Data
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
is set and the answer needs it. Selecting one view bounds the address-keyed requests to that
view. With every view selected, request counts can grow with the grid's view count; the
`subnet` and `fqdn` counts above describe their collection requests.

## IPv6

`ip`, `subnet`, `ping` and Bulk DNS Lookup take IPv6 addresses and prefixes, in the menu and on the
command line, and so do bare objects. `fqdn` and `site` always did. Network views work unchanged.

```bash
cn 2001:db8:20::5 2001:db8:20::1:a --format md
cn subnet 10.20.0.0/24 2001:db8:20::/64 --format json
cn ping 2001:db8:20::5 web06.example.net --tcp 443
cn ping fe80::1%eth0
```

An IPv4-only run sends the same requests and prints the same output as 0.4.x, except that `subnet`
also lists every used address in its `IP addresses` section (one more request for each network).

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
  identity. It appears in `ip` and in the `fixed addresses` and `IP addresses` of `subnet` whenever
  the run looks up an IPv6 object, empty for an IPv4 row, and an IPv4-only run has none. Like `tcp_<port>`, it
  follows the input, not the data: read it with `.duid // ""`. DHCPv6 options are shown as
  returned, not decoded.
- **Unused addresses and PTR names.** `ip` shows a row for each IPv6 address for which the grid
  returns an object (whatever its status) and a `not_found` line `No matching IPv6 record found`
  when it returns none, or `No Infoblox network contains this address` when no network holds it
  (the reason an IPv4 address has too). `PTR name` comes from `record:ptr?ipv6addr=`, asked for each IPv6 address
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
