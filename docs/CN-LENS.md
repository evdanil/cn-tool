# cn-lens

## Purpose

`cn-lens` is a task-first network object lens for network designers, IPAM, and
ops teams. It accepts common network object inputs, classifies them, and renders
inspection evidence in human-readable and structured formats.

## Relationship to cn-tool

The classic `cn-tool` menu remains available for existing workflows. `cn-lens`
is workflow-first: commands are designed around specific jobs and can reuse the
same repository and configuration foundations over time.

## Quick start

```bash
cn-lens
cn-lens 10.10.10.5
cn-lens inspect 10.10.10.5 10.10.20.0/24 router1.example.net
cn-lens inspect --file objects.txt
cat objects.txt | cn-lens inspect - --format json
cn-lens inspect --file objects.csv --column target --format xlsx --output evidence.xlsx
cn-lens interactive
cn-lens --version
```

## Object types

`cn-lens` recognizes IP addresses, prefixes (CIDR), FQDNs, site codes, and
device names. Invalid inputs are reported without stopping valid inputs from
being processed.

## Batch input

Batch input can come from positional arguments, one or more `--file` values, a
CSV `--column`, or stdin with `-`. Input order is preserved across mixed sources
as written on the command line, and duplicates are counted.

## Workflow catalog

### `inspect`

Classify network objects and render an offline inspection run. Accepts IPs,
prefixes, FQDNs, site codes, and device names. Results carry classification
type, normalized value, notes, and per-source status.

In online mode, PREFIX objects query Active Directory for an `ad` enrichment
block containing `site`, `location`, and `description` from AD subnet attributes.

```bash
cn-lens inspect 10.0.0.1
cn-lens inspect 10.0.0.1 10.0.0.0/24 host.example.net
cn-lens inspect 10.0.0.0/24 --deep
cn-lens inspect - --format json
cn-lens inspect --file objects.txt --format md
cn-lens inspect --file data.csv --column target --format xlsx --output out.xlsx
```

Flags:
- `--deep` — deep-dive for PREFIX and IP objects: fans out to DHCP ranges with
  failover associations, fixed addresses, in-subnet DNS records, member
  assignments, and decoded DHCP options. For bare IP targets, also calls
  `contains_address` to surface the parent subnet. For container prefixes,
  expands child networks. When `--format xlsx` is used, a `Subnet Data Detail`
  sheet is added to the workbook (parity with the cn-tool subnet request module).

### `impact`

Find all references to objects across available sources: config repository,
SD-WAN YAML, Infoblox containers, and AD group memberships. Findings are
grouped by source. A `summary["impact"]["matches"]` table is populated for
renderers to emit structured output.

```bash
cn-lens impact 10.1.0.0/24
cn-lens impact 10.1.0.0/24 --all-matches
cn-lens impact SITE01 --format json
cn-lens impact --file prefixes.txt --format xlsx --output impact.xlsx
```

Flags:
- `--all-matches` — return all SD-WAN YAML prefix matches across every file
  instead of the single best match. Applies to PREFIX and IP objects. Default
  behaviour returns only the single best match per prefix.

### `dns`

Resolve DNS and Infoblox DNS records for network objects. Performs forward
lookups, reverse (PTR) lookups, and FQDN prefix expansion mirroring the
`fqdn_request` module semantics. Results are collected in
`summary["dns"]` blocks with name→IP and IP→name maps.

For IP targets the reverse block now includes an `aliases` list alongside the
`ptr` field.

For FQDN targets a `reverse_check` map is populated: each forward-resolved IP is
reverse-resolved and compared back to the queried FQDN (bidirectional
verification). Each entry carries `ptr` and `match` (bool).

```bash
cn-lens dns host.example.net
cn-lens dns 10.0.0.1 --format json
cn-lens dns --file hosts.txt
```

### `reachability`

Perform reachability checks (ping and/or traceroute) for network objects.

PREFIX objects probe up to `--max-hosts` host IPs (default 32; 0 = full
expansion). A warning finding is emitted when the prefix contains more host IPs
than the effective cap. The batch result carries `batch_status` (`ok` |
`partial` | `failed`) and `reachable_count`.

When Infoblox is configured and mode includes tracing, each trace result is
enriched with a `site_verdict` field (`valid` | `site_mismatch` |
`site_unknown`) derived from Infoblox extattr `Site` lookups on the target IP
and last responding hop. When Infoblox site data is absent, AD site codes are
used as a fallback for hop annotation.

FQDN targets resolve forward DNS first; the `reached` flag in trace results is
corrected by comparing the last hop IP against the full set of resolved IPs
(hostname-target reached fix).

```bash
cn-lens reachability 10.0.0.1
cn-lens reachability 10.0.0.1 --mode trace
cn-lens reachability 10.0.0.1 --mode trace --probe mtr
cn-lens reachability 10.0.0.0/24 --max-hosts 0
cn-lens reachability --file hosts.txt --mode both --format json
```

Flags:
- `--mode ping|trace|both` — probe mode (default: `ping`).
- `--max-hosts N` — maximum host IPs to probe for PREFIX objects (0 = full
  expansion, default: 32).
- `--probe traceroute|mtr` — trace tool (default: `traceroute`). `mtr` requires
  the `mtr` binary in PATH; degrades gracefully with a `not_configured` finding
  when the binary is absent.

### `device`

Classify and enrich device-oriented network objects by combining AD OU path,
Infoblox host records, and config repository references. Use `--probe` to
additionally test reachability of resolved IPs. Use `--collect` to SSH-connect
and gather serial, software version, image, and license data (parity with the
cn-tool "Device Information Request" module).

The workflow accepts DEVICE, IP, FQDN, SITE, and PREFIX objects. For an IP
input the adapter resolves the hostname via reverse-DNS + AD lookup, then runs
the full device chain on that hostname. For a FQDN with fewer than three
dot-separated labels the object is treated as a short device hostname. Bare
site codes and prefixes produce a classifier-only finding directing the user to
the appropriate workflow.

**`--collect` detail.** When `collect=True` the workflow SSH-connects via
the `device_ssh` adapter and runs platform-specific show commands:

- IOS-XE: `show version`, `show license reservation`, `show license summary`,
  `show license`
- NX-OS: `show version`, `show license all`

Results are stored under `summary["collect"]` with fields matching the
cn-tool "Device Data" columns: `serial`, `version`, `image`, `license`
(list of `{name, status, type, count}` dicts), `platform`, and `uptime`.
When `device_ssh_enabled` is absent or falsy the collect block carries
`{"status": "not_configured"}` and no SSH connection is attempted.

For IP-path inputs (IP object whose reverse-DNS hostname is resolved) the
`collect` block is surfaced in `summary["device"]["collect"]`. Probe results
from the secondary device chain are not surfaced in `summary["device"]` — only
`ad`, `infoblox`, `config_repo`, and `collect` appear there (see Deliberate
deviations, M7).

**Offline / `--offline` flag.** Accepted on this subparser in trailing
position (`cn-lens device ... --offline`) as well as the global position
(`cn-lens --offline device ...`). In offline mode all adapters return
`not_queried` and no SSH connections are made.

```bash
cn-lens device router1.example.net
cn-lens device router1.example.net --probe
cn-lens device router1.example.net --collect
cn-lens device router1.example.net --collect --probe
cn-lens device --file devices.txt --format xlsx --output devices.xlsx
cn-lens device router1.example.net --offline
```

Flags:
- `--probe` — ping resolved IPs (default: false).
- `--collect` — SSH-connect and collect show version / license data (default:
  false). Requires `device_ssh_enabled = true` in config. Degrades gracefully
  when SSH is not configured.

### `e911`

Collect E911 stack member MAC addresses from network switches via SSH. The
workflow accepts any IP, FQDN, or device-name targets, connects to each via
the `device_ssh` adapter (`show switch`), and returns per-stack-member MAC
addresses in both colon (`AA:BB:CC:DD:EE:FF`) and dot (`AABB.CCDD.EEFF`)
notation. Multiple stack members per device are returned as separate rows in
`summary["e911"]["members"]`.

Per-device error isolation: a failed SSH connection on one device does not
prevent other devices in the same batch from being collected. Each device's
summary either contains a `members` list or a single-key error dict
(`{"error": "<message>"}`) or a not-configured dict
(`{"status": "not_configured"}`).

Colon and dot MAC formats follow `normalize_mac_format` from
`utils/parsers.py`; the colon format is canonical and dot format is derived
from it.

When `device_ssh_enabled` is absent or falsy in config the per-device summary
carries `{"status": "not_configured"}` and no SSH connection is attempted.

**Offline / `--offline` flag.** Accepted on this subparser. In offline mode
all devices return `{"status": "not_configured"}` sources.

```bash
cn-lens e911 10.0.0.1
cn-lens e911 10.0.0.1 10.0.0.2 switch01.example.com
cn-lens e911 10.0.0.1 --format json
cn-lens e911 --file switches.txt --format xlsx --output e911.xlsx
```

### `validate-site`

Validate site objects for consistency across Active Directory, SD-WAN YAML,
Infoblox, config repository, and DNS. Reports per-check pass/fail in
`summary["validate_site"]`.

```bash
cn-lens validate-site SITE01
cn-lens validate-site SITE01 SITE02 --format json
```

### `decommission-site`

Run decommission-readiness checks for site objects. Active Infoblox prefixes,
config repository references, AD accounts, or DHCP scopes block decommission
and are reported as `error` findings. A fully clean site produces an `info`
finding: "safe to decommission".

```bash
cn-lens decommission-site SITE01
cn-lens decommission-site SITE01 --format json
```

### `allocate`

Safety-check a candidate prefix before allocation in Infoblox. Confirms the
prefix is available, has no overlap with existing networks, passes inheritance
checks, and the target AD site can host it.

```bash
cn-lens allocate 10.5.0.0/24 --target-site SITE01
cn-lens allocate 10.5.0.0/24 --format json
```

Flags:
- `--target-site SITE_CODE` — destination site for the allocation.

### `bssid`

Convert wired Ethernet MAC addresses to Aruba BSSID radio MACs (2.4 GHz and
5 GHz). This command is offline-always: no live adapters are contacted.

Accepted MAC formats (case-insensitive): `xx:xx:xx:xx:xx:xx`,
`xx-xx-xx-xx-xx-xx`, `xxxx.xxxx.xxxx`, `xxxxxxxxxxxx`. Invalid tokens are
captured as invalid inputs and do not affect exit code for valid MACs.

```bash
cn-lens bssid d0:4d:c6:c8:6d:6e
cn-lens bssid d0:4d:c6:c8:6d:6e aa:bb:cc:dd:ee:ff
cn-lens bssid d0:4d:c6:c8:6d:6e --format json
cn-lens bssid --file macs.txt --format xlsx --output bssids.xlsx
```

### `config find`

Search config repository and SD-WAN YAML for the given query strings. Each
query term is treated as a case-insensitive regex pattern (falling back to
literal match if it fails to compile). Multiple terms are searched in a single
pass over each file; vendor stop-words suppress noise matches.

Results report `source_status` (`indexed` when served from a cache index, `live`
when from a live file-system scan) and per-term `matched` / `missed` statistics.
One `LensResult` is emitted per query object.

When `--format xlsx` is used:
- Up to 50 matched devices each receive a full-config tab with a `HYPERLINK`
  formula in the Matches sheet pointing to the matching line.
- When more than 50 devices match, only the Matches sheet is written (no
  per-device config tabs, no hyperlinks).

```bash
cn-lens config find 10.1.0.0/24
cn-lens config find SITE01 --scope cfg --limit 20
cn-lens config find bgp --format json
cn-lens config find bgp ospf --format xlsx --output search.xlsx
```

Flags:
- `--scope all|cfg|yaml` — search scope (default: `all`).
- `--limit N` — maximum matches per query.

### `config diff`

Diff two snapshots for a device. By default locates the two most recent
snapshots automatically; use `--snapshots` to supply explicit paths.

Exit semantics (pipeline-friendly, like `diff(1)`):
- `0` — snapshots are identical.
- `1` — snapshots differ.
- `2` — error (snapshot not found, read failure, or usage error).

```bash
cn-lens config diff router01
cn-lens config diff router01 --repo-root /opt/config-repo
cn-lens config diff router01 --snapshots /repo/history/r1/v1.cfg /repo/r1.cfg
cn-lens config diff router01 --side-by-side --context 5
cn-lens config diff router01 --format json
```

Flags:
- `--repo-root PATH` — root of the config repository.
- `--snapshots A B` — explicit snapshot file paths (skips auto-discovery).
- `--side-by-side` — include a side-by-side text diff in the output.
- `--context N` — context lines (default: 3).

### `config get`, `config set`, `config test`

Inspect and update the active `.cn` configuration, and probe connectivity.

```bash
cn-lens config get
cn-lens config get api_endpoint
cn-lens config set api_endpoint https://infoblox.example.com/wapi/v2.11
cn-lens config test
```

`config get [KEY]` — show one or all current config values. Secret keys
(containing "password", "credentials", "secret", or "privkey") are redacted to
`***`.

`config set KEY VALUE` — write `KEY=VALUE` to the user config layer (`~/.cn`).
Key is validated against the config schema before writing.

`config test` — probe Infoblox API and Active Directory connectivity (same
probes as `doctor`). In offline mode both sources are reported as `disabled`.

### `report`

Bundle one or more persisted `LensRun` objects into a `LensReport` aggregate.
Use `--from-last` to include the most recent run, or `--include` to name
specific run IDs. Optionally send the rendered report via the email plugin.

Use `--prune` to clean up old persisted runs from the lens directory. Use
`--delete` to remove a single run by its ID (strict run-id validation;
operations are scoped to the configured lens directory).

```bash
cn-lens report --from-last
cn-lens report --from-last --format xlsx --output report.xlsx
cn-lens report --include 20260511T120000Z --email ops@example.com
cn-lens report --prune --keep 10
cn-lens report --prune --older-than 30
cn-lens report --delete 20260511T120000Z
```

Flags:
- `--from-last` — include the most recently persisted run.
- `--include RUN_ID` — add a specific run (repeatable).
- `--email ADDR` — send via email plugin if loaded.
- `--prune` — prune persisted runs (requires `--keep` or `--older-than`).
- `--keep N` — keep the N newest runs (use with `--prune`).
- `--older-than DAYS` — delete runs older than DAYS days (use with `--prune`).
- `--delete RUN_ID` — delete a single run by ID.

### `stats`

Display cn-tool/cn-lens shared usage statistics. Reads and aggregates per-user
session files from the configured stats directory. Sessions are finalized at
the end of each run; raw session data is excluded from the output (privacy).
This command is offline-capable: no live adapters are consulted.

```bash
cn-lens stats
cn-lens stats --period 7d
cn-lens stats --period all --format json
cn-lens stats --format xlsx --output stats.xlsx
```

Flags:
- `--period all|7d|4w|1m|12m` — reporting period (default: `all`).

cn-lens reads statistics when any of `collect_enabled`, `menu_enabled`, or `directory` is set in `[stats]` — the `stats` command is usable as long as `directory` points to an accessible stats tree.

Requires stats collection to be enabled in `.cn`:

```ini
[stats]
collect_enabled = true
directory = /shared/stats
```

## Output formats

Supported formats are `human`, `text`/`txt`, `md`/`markdown`, `json`,
`yaml`/`yml`, and `xlsx`. The `xlsx` format requires `--output`.

Select with `--format`. Write to file with `--output PATH`.

## Structured output contract

Structured output includes:

- `schema_version` — always `1` in the current release.
- `tool` — always `"cn-lens"`.
- `workflow` — name of the workflow that produced the run.
- `run_id` — UTC timestamp string (`YYYYMMDDTHHmmSSZ`).
- `inputs` — classified and invalid objects plus duplicate count.
- `results` — per-object `LensResult` with status, summary, findings, and sources.
  Every result's `status` field is uniformly `"classified"` across all workflows.
  Consumers keying on the old values `"searched"` or `"reported"` must update
  their logic to use `"classified"` instead.
  The `config find` workflow emits one `LensResult` per input query object
  (previously results were collapsed into a single row).
- `warnings` — run-level warning strings.
- `errors` — run-level error strings.

## Per-workflow renderer extensions

### Markdown

When a `LensResult` summary contains a workflow-specific key (e.g. `"impact"`,
`"dns"`, `"reachability"`, `"device"`, `"validate_site"`, `"decommission_site"`,
`"allocate"`, `"config_find"`, `"config_diff"`, `"report"`, `"bssid"`,
`"stats"`, `"e911"`), `render_markdown` emits a fenced YAML block under a
`#### Workflow: <key>` heading instead of inlining the summary as JSON. This
keeps the rendered document readable for complex nested data.

### xlsx

When any result carries a workflow-specific summary key, `write_xlsx` adds a
`Per-Workflow` sheet with columns `(object, workflow, key, value)`. Each nested
key-value pair under the workflow block becomes a row with the object value in
column A. This sheet is omitted for runs that carry no workflow-specific summary
keys (e.g. plain `inspect` runs without `--deep`).

When `inspect --deep` is used and any result contains deep Infoblox data, a
`Subnet Data Detail` sheet is added to the workbook. This sheet mirrors the
layout of the cn-tool subnet request module and contains one main row per
subnet plus secondary rows for in-subnet DNS records and fixed addresses.

When `config find --format xlsx` is used with up to 50 matched devices, each
device receives a full-config tab and the Matches sheet contains `HYPERLINK`
formulas pointing to the matching lines. When more than 50 devices match, only
the Matches sheet is written with plain line numbers (no tabs, no hyperlinks).

## Offline mode

Pass `--offline` (global flag) to skip every adapter. No authentication, no
network calls, no config repository reads. Classification still runs; results
carry `not_queried` source status. Useful for testing, scripting, and
air-gapped environments.

```bash
cn-lens --offline inspect 10.0.0.1
cn-lens --offline impact --file objects.txt
```

In offline mode `LensRuntime.ensure_credentials(scope)` raises `RuntimeError`
rather than prompting for credentials. Adapters short-circuit before the raise.

The following commands are offline-capable by design (they do not contact live
adapters regardless of the `--offline` flag):

- `bssid` — pure arithmetic MAC→BSSID conversion.
- `stats` — reads local stats files only; no network calls.

## Enabling adapters and live data

By default, `cn-lens` runs in online mode but each adapter is individually gated
on its own config keys.  A missing key degrades that adapter to `not_configured`
health — classification still runs, all other adapters that are configured still
run, and the finding on every result reads:

```
object classified; see sources block for adapter health and summary block for adapter results
```

This is normal and expected when the `.cn` file is absent or incomplete.

### Default behaviour with no config

Running `./cn-lens.py impact 10.0.0.1` with no `.cn` file:

- All adapters return `not_configured` or `disabled` status in `LensResult.sources`.
- Summary blocks are present but adapter data fields are empty or absent.
- Each result carries one classifier finding with the message above.
- No credentials are prompted; no network calls are made.

Running `./cn-lens.py --offline impact 10.0.0.1` additionally disables all
adapters regardless of config (see [Offline mode](#offline-mode)).

### `.cn` config file location

Config lookup is layered (lowest → highest precedence):

1. A `.cn` file next to the `cn-lens.py` script.
2. `~/.cn` in the user home directory.
3. A path passed via `--config PATH` on the command line.

Later entries override earlier ones.  The existing cn-tool documentation covers
the full INI format; all `cn-lens` adapters read from the same file.

### Per-adapter config keys

| Adapter | Required key(s) | Section / shape | Health when key missing |
| ------- | --------------- | --------------- | ----------------------- |
| **Infoblox** | `api_endpoint` | `[api]` → `endpoint = https://<wapi-host>/wapi/v2.11` | `not_configured` |
| **Active Directory** | `ad_enabled = true`, `ad_uri` | Top-level INI keys; `ad_uri = ldap://<dc-host>` | `not_configured` |
| **config_repo** | `config_repo_enabled = true`, `config_repo_directory` | Top-level INI keys; `directory = /path/to/repo` | `not_configured` |
| **sdwan_yaml** | `sdwan_yaml_repo_paths` | Top-level; comma-separated paths (legacy: `sdwan_yaml_repo_path`) | `not_configured` |
| **DNS** | — (none) | Uses system resolver; always available online | `ok` |
| **Reachability** | — (none) | Uses system `ping` / `traceroute` binaries | `error` if binary missing |
| **device_ssh** | `device_ssh_enabled = true` | Top-level INI key; opt-in, default absent | `not_configured` |

Additional optional keys:

| Key | Adapter | Description |
| --- | ------- | ----------- |
| `ad_search_base` | AD | LDAP search base DN (default: auto-derived from domain). |
| `ad_operation_timeout` | AD | Per-operation LDAP timeout in seconds. |
| `ad_user` | AD | Bind username; prompted at runtime if absent. |
| `config_repo_excluded_dirs` | config_repo | Comma-separated directory names to skip. |
| `config_repo_vendors` | config_repo | Comma-separated vendor filters applied during search. |
| `config_repo_history_dir` | config_repo | Sub-directory name for history snapshots (default: `history`). |
| `config_search_max_workers` | config_repo | Thread-pool size for parallel file scanning (default: 8). |
| `site_dns_suffix` | DNS, validate-site | DNS suffix appended to bare site codes for forward lookups. |
| `[api] verify_ssl` | Infoblox | TLS verification; set `false` to disable cert checks. |
| `[api] timeout` | Infoblox | Per-request timeout in seconds. |
| `device_query_workers` | device_ssh | Thread-pool size for concurrent SSH collection (default: 10). |

### Minimal `.cn` example

Copy and substitute before use.  Keys marked `<...>` are required for that
adapter; keys on their own line (no `<...>`) can be omitted to leave the
adapter disabled.

```ini
[api]
endpoint = https://<infoblox-wapi-host>/wapi/v2.11
verify_ssl = true
timeout = 30

ad_enabled = true
ad_uri = ldap://<domain-controller-hostname>
ad_search_base = DC=<domain>,DC=<tld>

config_repo_enabled = true
config_repo_directory = /opt/config-repo

sdwan_yaml_repo_paths = /opt/sdwan-yaml

site_dns_suffix = <your.internal.domain>
```

Credentials (Infoblox username/password, AD bind password) are never stored in
`.cn`; they are prompted at runtime and cached securely by the cn-tool credential
layer.

### Quick sanity check

After adding config, run:

```bash
./cn-lens.py doctor
```

`doctor` reports live adapter health.  It currently returns informational output
only (no remediation steps).

To see per-adapter health for a real object, inspect the `sources` block of any
workflow output:

```bash
./cn-lens.py inspect 10.0.0.1 --format json | python3 -c "
import sys, json
run = json.load(sys.stdin)
for r in run['results']:
    print(r['sources'])
"
```

A healthy online run looks like:

```json
{"classifier": "ok", "infoblox": "ok", "ad": "ok", "config_repo": "ok", "dns": "ok", "reachability": "ok", "sdwan_yaml": "ok", "device_ssh": "ok"}
```

An adapter with missing config appears as `"not_configured"` rather than `"ok"`.

## Runtime configuration keys

`cn-lens` honors these `.cn` configuration keys at runtime:

| Section / Key                 | Workflow(s)             | Description |
| ----------------------------- | ----------------------- | ----------- |
| `[api] endpoint`              | All live workflows      | Infoblox WAPI endpoint. |
| `[api] verify_ssl`            | All live workflows      | TLS verification for Infoblox calls. |
| `[api] timeout`               | All live workflows      | Per-request timeout in seconds. |
| `[api] max_workers`           | All live workflows      | Concurrent Infoblox worker ceiling. |
| `[config_repo] enabled`       | impact, config find, device, validate-site, decommission-site, allocate | Enable config repository searches. |
| `[config_repo] directory`     | Same as above           | Root directory of the config repository. |
| `[ad] enabled`                | device, validate-site, decommission-site, allocate, reachability, inspect | Enable AD enrichment. |
| `[ad] uri`                    | Same as above           | LDAP URI for Active Directory. |
| `[cache] enabled`             | All live workflows      | Enable disk-based result cache. |
| `[cache] directory`           | All live workflows      | Cache root directory. |
| `[report] filename`           | report                  | Default output filename for reports. |
| `output_dir`                  | report                  | Root directory for persisted runs (`<output_dir>/cn-lens/<run_id>/run.json.gz`). |
| `site_dns_suffix`             | dns, validate-site      | DNS suffix appended when expanding bare site codes to FQDNs. |
| `[stats] collect_enabled`     | stats                   | Enable stats collection (shared with cn-tool). |
| `[stats] directory`           | stats                   | Root directory for shared stats files. |

Use `--config PATH` to point at a non-default `.cn` file.

## Exit codes

- `0` — success, with at least one valid object (or for `report`, successful bundle).
- `1` — no valid objects, no input, or no runs available to bundle. For `config diff`, snapshots differ.
- `2` — usage error, I/O error, or render failure. For `config diff`, error (snapshot not found or read failure).

The same codes apply in the interactive shell's per-command return values.

## Persistence layout

Every workflow run is optionally persisted as a gzip-compressed JSON file:

```
<output_dir>/cn-lens/<run_id>/run.json.gz
```

The `report` workflow reads persisted runs by run_id. Run IDs are UTC timestamp
strings (`YYYYMMDDTHHmmSSZ`).

## Schema version

The current schema version is `1`. Future breaking changes will increment this
field. Consumers should check `schema_version` before processing structured
output.

## Email plugin integration

The `report` workflow accepts `--email TO_ADDR` to send rendered reports via the
email plugin. The plugin is duck-typed via a `Protocol`; if the plugin is not
loaded (not configured or disabled), an `info` finding is emitted and the command
returns `0`.

## Interactive mode

Running `cn-lens` without arguments starts the interactive shell. `cn-lens
interactive` is the explicit equivalent.

```text
cn-lens> 10.10.10.5
cn-lens> inspect 10.10.10.5 --format json
cn-lens> inspect 10.0.0.0/24 --deep
cn-lens> impact SITE01
cn-lens> dns host.example.net
cn-lens> device router1.example.net --collect
cn-lens> e911 10.0.0.1 10.0.0.2
cn-lens> bssid d0:4d:c6:c8:6d:6e
cn-lens> stats --period 7d
cn-lens> set format json
cn-lens> report --from-last
cn-lens> report --prune --keep 10
cn-lens> config find bgp --scope cfg
cn-lens> config diff router01
cn-lens> config get
cn-lens> config set api_endpoint https://infoblox.example.com/wapi/v2.11
cn-lens> config test
cn-lens> export last --format md --output result.md
cn-lens> history
cn-lens> help
cn-lens> help impact
cn-lens> quit
```

### Shell commands

| Command                        | Description |
| ------------------------------ | ----------- |
| `inspect [<objects>]`          | Classify objects (default for bare inputs). |
| `inspect ... --deep`           | Deep-dive for PREFIX/IP: DHCP, fixed addresses, DNS, members. |
| `impact <object>`              | Find cross-source references. |
| `impact ... --all-matches`     | Return all SD-WAN prefix matches (exhaustive mode). |
| `dns <object>`                 | Resolve DNS/Infoblox records. |
| `reachability <object>`        | Ping/trace reachability. |
| `device <object>`              | Enrich device objects. |
| `device ... --collect`         | SSH-collect serial/version/image/license data. |
| `e911 <device>...`             | Collect E911 stack member MAC addresses via SSH. |
| `validate-site <site>`         | Validate site consistency. |
| `decommission-site <site>`     | Decommission readiness check. |
| `allocate <prefix>`            | Safety-check prefix allocation. |
| `bssid <mac>...`               | Convert wired MAC to Aruba BSSID (offline). |
| `config find <query>`          | Search config repo / SD-WAN YAML. |
| `config diff DEVICE`           | Diff two device snapshots. |
| `config get [KEY]`             | Show config values (secrets redacted). |
| `config set KEY VALUE`         | Write a value to `~/.cn`. |
| `config test`                  | Probe Infoblox + AD connectivity. |
| `report [--from-last] [...]`   | Bundle persisted runs. |
| `stats [--period ...]`         | Show usage statistics (offline). |
| `set format <fmt>`             | Change default output format. |
| `export last --format <fmt> --output <path>` | Export last run. |
| `history`                      | Show session command history. |
| `doctor`                       | Check live adapter health. |
| `help [command]`               | Show command list or per-command usage. |
| `quit` / `exit`                | Leave the shell. |

### Autocomplete

Tab autocomplete is available when the Python `readline` module is present
(standard on Linux/macOS). Completions include all workflow names, `set`,
`export`, `history`, `help`, `doctor`, `quit`, and `exit`. On Windows without
pyreadline, autocomplete silently degrades to no-op.

## SSH adapter (device_ssh)

`cn-lens` ships a dedicated SSH adapter (`cn_lens/adapters/device_ssh.py`)
that connects to network devices using netmiko's `ConnectHandler` with
`SSHDetect` autodetect, porting the connection flow from
`modules/device_query.py`.

### Enabling the SSH adapter

The adapter is opt-in. Add the following key to `.cn` to enable it:

```ini
device_ssh_enabled = true
```

Without this key the adapter health is `not_configured` and no SSH
connections are attempted. The `device --collect` and `e911` workflows
degrade gracefully in this state.

### Config keys

| Key | Default | Description |
| --- | ------- | ----------- |
| `device_ssh_enabled` | absent (disabled) | Set to `true` to enable SSH collection. The adapter is opt-in; health is `not_configured` when this key is absent or falsy. |
| `device_query_workers` | `10` | Maximum concurrent SSH sessions (ThreadPoolExecutor bound). Shared with cn-tool's device_query module. |

### Credential scope

Credentials for the SSH adapter use the `device` scope — the same TACACS
credential path used by cn-tool's Device Information Request module. The GPG
decryption path is identical to the `ad` scope. Credentials are acquired once
on the main thread before the worker pool is launched; individual workers reuse
the cached credentials without prompting.

```python
username, password = runtime.ensure_credentials("device")
```

If credential acquisition fails the entire batch returns an error result
immediately; no SSH connections are attempted.

### Autodetect flow

1. An initial `SSHDetect` connection determines the platform type.
2. The detected type is mapped to a platform family:
   - Any type containing `"nxos"` → `"nxos"`
   - Any type containing `"cisco"` (e.g. `cisco_ios`, `cisco_xe`, `cisco_xr`)
     → `"iosxe"`
   - Any other type → error result, no further connection.
3. A `ConnLogOnly` connection is opened with the detected type.
4. Per-platform commands are executed and their output is parsed by callables
   from `utils/parsers.py`.

### Health states

The `DeviceSshAdapter.health()` method returns one of:

| State | When |
| ----- | ---- |
| `disabled` | Runtime is in offline mode. |
| `not_configured` | `device_ssh_enabled` is absent or falsy in config. This is the default state — the adapter is opt-in. |
| `ok` | `device_ssh_enabled` is truthy; credentials will be acquired on first use. |

### Per-device error isolation

Each device in a batch is collected independently. An SSH failure (connection
refused, authentication error, autodetect failure, timeout) for one device:
- Produces an error result dict `{device: "<error message>"}` for that device.
- Leaves all other devices in the batch unaffected.
- Is logged at INFO level (not propagated as an exception).

### Deliberate deviation: no reverse-DNS device-name gate

The cn-tool donor `process_device_commands` (in `modules/device_query.py`)
applies a reverse-DNS gate: only devices whose DNS name matches the pattern
`(es|mp|vi|bl|sp|lf)\d{3}` are collected. `cn-lens` omits this gate
intentionally — `device --collect` and `e911` accept any reachable target
(IP address, FQDN, or arbitrary hostname). See Deliberate deviations below.

## Doctor / sources contract

### Per-adapter health states

`doctor` (and every `LensResult.sources` dict) uses the unified status
vocabulary defined in `cn_lens/adapters/types.py`. Both `VALID_SOURCE_STATUSES`
(adapter-level availability) and `VALID_RESULT_STATUSES` (per-lookup outcome)
are in that file; the two vocabularies overlap intentionally but serve different
purposes.

**`VALID_SOURCE_STATUSES`** — used in `AdapterHealth.status` and
`LensResult.sources` values:

| Status | Meaning |
| ------ | ------- |
| `ok` | Adapter is configured and healthy. |
| `partial` | Adapter returned results but with some degradation (e.g. some hosts in a batch failed). |
| `error` | Adapter is configured but the health check or connection failed. |
| `not_configured` | Required config key(s) are absent or falsy. No network call attempted. |
| `not_queried` | Adapter was not consulted for this run (offline mode, or adapter disabled for this workflow path). |
| `disabled` | Runtime is in offline mode; the adapter is unconditionally skipped. |

### How `doctor` works

`doctor` iterates the shared adapter registry (seven adapters: `infoblox`,
`ad`, `config_repo`, `dns`, `reachability`, `sdwan_yaml`, `device_ssh`) and
reports health in two stages:

1. **Cheap config-only check** — each adapter's `health(runtime)` method
   inspects config keys without making network calls. All adapters run this
   stage.
2. **Deep connectivity probe** — for adapters that have a `deep_health`
   callable (currently `infoblox` and `ad`) the cheap status is upgraded by
   actually probing the endpoint (HTTP grid check for Infoblox; LDAP bind for
   AD). Deep probes include credential acquisition internally. Deep probes are
   skipped when the cheap check already returned `not_configured` or `disabled`.

In offline mode (`--offline` or `runtime.offline = True`) every adapter
returns `not_queried` immediately; no probes run and no credentials are
requested.

`doctor` exits `0` in all normal cases (unconfigured adapters are
informational, not failures) and `2` only on an internal error.

### Per-workflow `sources` semantics

Every `LensResult.sources` dict is built by `AdapterRegistry.source_statuses()`
and has one entry per registered adapter plus a `"classifier"` entry:

```json
{
  "classifier": "ok",
  "infoblox": "ok",
  "ad": "not_configured",
  "config_repo": "ok",
  "dns": "ok",
  "reachability": "ok",
  "sdwan_yaml": "not_configured",
  "device_ssh": "not_configured"
}
```

In **online mode** the registry calls each adapter's `health(runtime)` method
to determine the live status. In **offline mode** (`--offline` global flag)
every adapter returns `not_queried` without any health check being run.

The `sources` dict is **shared across all results in a run** — it reflects
adapter availability at run time, not per-object query outcomes. Per-object
query outcomes are in `LensResult.summary` and `LensResult.findings`.

### Effect of `--offline` on sources

When any standard workflow subparser receives `--offline` (trailing position)
or when the global `--offline` flag is set, `runtime.offline` is `True`.
`run_workflow` in `_helpers.py` takes the offline path, and
`registry.source_statuses(runtime, offline=True)` returns `not_queried` for
every adapter. `LensRuntime.ensure_credentials(scope)` raises `RuntimeError`
on the offline path rather than prompting. Adapters short-circuit before
reaching any `ensure_credentials` call.

## Deliberate deviations

The following are intentional differences between cn-lens and cn-tool behaviour.
Each is documented here for operator awareness; none represent missing features.

| # | Area | cn-tool behaviour | cn-lens behaviour | Rationale |
| - | ---- | ----------------- | ----------------- | --------- |
| D9-1 | Trace tool | `traceroute` only | `traceroute` default; `--probe mtr` when binary present | mtr optional; graceful degradation with `not_configured` finding when absent |
| D9-2 | WAPI result cap | `_max_results=1000` | Same cap kept | cn-tool parity; avoids accidental full-table scans |
| D9-3 | Ping verdict | OK on any ICMP reply | `ok / partial / failed` with `partial` counted as reachable | Richer data; capability parity with clearer semantics |
| D9-4 | SD-WAN YAML match | Plugin always returns all matches (exhaustive) | Default returns single best match; `--all-matches` flag for exhaustive output | Predictable default for single-prefix lookups; opt-in exhaustive mode |
| D9-5 | SSH device-name gate | `process_device_commands` rejects devices whose reverse-DNS name does not match `(es|mp|vi|bl|sp|lf)\d{3}` | No gate applied; any reachable target is accepted | cn-lens is target-agnostic; operator supplies the target list |
| M7 | Device IP-path probe | n/a (cn-tool does not have an IP-path device chain) | Probe results from the secondary device chain (IP → hostname → device) are not surfaced in `summary["device"]`; only `ad`, `infoblox`, `config_repo`, and `collect` appear there | Keeps the IP-path device sub-object compact; ping findings are present in the top-level `findings` list |
| CF-1 | config find xlsx | Per-device config tabs always written | Up to 50 matched devices receive full-config tabs + `HYPERLINK` formulas; above 50 only the Matches sheet is written (no tabs, no hyperlinks) | Prevents workbook size explosion for broad search terms |

## cn-tool parity matrix

The table below maps every cn-tool module and plugin to its cn-lens equivalent.
"Full" means end-to-end feature parity; "Partial" means the core flow is
covered but one or more secondary features differ (see notes); "Not ported"
means no lens command covers this feature.

All cn-lens commands in the "Lens command(s)" column have been verified to exist
in `cn_lens/commands.py`.

### Modules

| cn-tool module (menu title) | File | Lens command(s) | Status | Notes |
| --------------------------- | ---- | --------------- | ------ | ----- |
| IP Information (IPv4) | `modules/ip_request.py` | `inspect`, `inspect --deep` | Full | `inspect` covers IP lookup; `--deep` adds DHCP/fixed-address/DNS fan-out matching Subnet Data Detail parity |
| Subnet Information | `modules/subnet_request.py` | `inspect --deep` | Full | Deep-dive fan-out (DHCP ranges, failover, fixed addresses, in-subnet DNS, member assignments, decoded DHCP options) + Subnet Data Detail xlsx sheet |
| FQDN Prefix Lookup | `modules/fqdn_request.py` | `dns` | Full | Forward + reverse lookups, PTR, aliases, bidirectional FQDN verification |
| Subnet Lookup (by site code or keyword) | `modules/location_request.py` | `inspect`, `impact` | Partial | `inspect` classifies site objects with AD enrichment; `impact` finds Infoblox subnet matches for a site code. Direct keyword-based subnet search is covered by `impact` + `config find`. |
| Configuration Lookup (by subnet or keyword) | `modules/config_search.py` | `config find` | Full | Config-repo + SD-WAN YAML search with scope filter (`--scope cfg/yaml/all`), regex patterns, vendor stop-words, source_status (indexed/live), xlsx with per-device tabs up to 50 devices |
| Config Repository Browser (TUI) | `modules/config_analyzer_module.py` | `config diff`, `config find` | Partial | Interactive TUI not ported (deliberate; out of scope). `config diff` covers snapshot diff with unified/side-by-side output; `config find` covers config search. |
| Device Information Request | `modules/device_query.py` | `device`, `device --collect` | Full | `device` covers AD OU path + Infoblox host records + config-repo references; `--collect` adds SSH serial/version/image/license (Device Data parity) |
| E911 Switch Information | `modules/e911_info.py` | `e911` | Full | SSH `show switch` collect, per-stack-member MAC in colon + dot formats, per-device error isolation |
| Aruba BSSID MACs | `modules/aruba_bssids.py` | `bssid` | Full | Offline MAC → 2.4 GHz + 5 GHz BSSID conversion; all four MAC input formats |
| Aruba DHCP scope/options tips | `modules/aruba_tips.py` | — | Not ported | Reference/tips display; no network data; not a query workflow |
| Bulk PING | `modules/bulk_ping.py` | `reachability` | Full | `reachability --mode ping` with `--file` batch input; `ok/partial/failed` verdict per target |
| Bulk DNS Lookup | `modules/bulk_resolve.py` | `dns` | Full | Forward + reverse DNS for batches via `--file` |
| Bulk Network Trace (MTR) | `modules/bulk_trace.py` | `reachability --mode trace` | Full | `--probe mtr` for mtr; `--probe traceroute` (default); `--file` batch; site-verdict enrichment |
| Site Demobilization Check | `modules/demob_check.py` | `decommission-site` | Full | Active prefixes, config refs, AD accounts, DHCP scopes block decommission; clean site → "safe to decommission" |
| Statistics Report | `modules/stats_report.py` | `stats` | Full | Shared per-user session files; `--period` filter; privacy model unchanged (raw sessions excluded) |
| Send Report via Email | `modules/manual_email.py` | `report --email` | Full | `report --email TO_ADDR` sends rendered report via email plugin duck-type |
| Application Setup | `modules/setup.py` | `config get`, `config set`, `config test` | Full | `config get/set` reads/writes `.cn`; `config test` probes Infoblox + AD; `doctor` for full adapter health |
| Delete Report | `modules/delete_report.py` | `report --delete`, `report --prune` | Full | `--delete RUN_ID` removes a single run; `--prune --keep N` / `--prune --older-than DAYS` bulk-prune |

### Plugins

| cn-tool plugin (plugin name) | File | Lens equivalent | Status | Notes |
| ----------------------------- | ---- | --------------- | ------ | ----- |
| Active Directory Support | `plugins/activedirectory_support.py` | AD adapter (`cn_lens/adapters/active_directory.py`) | Full | AD enrichment integrated into `inspect`, `impact`, `device`, `validate-site`, `decommission-site`, `allocate`, `reachability` workflows |
| Email Support | `plugins/email_support.py` | `report --email` | Full | Email plugin duck-typed via Protocol; `report --email TO_ADDR` sends rendered output |
| SD-WAN YAML Search | `plugins/sdwan_yaml_search.py` | sdwan_yaml adapter + `impact`, `config find` | Partial | Core YAML prefix search ported; plugin is always-exhaustive whereas lens default returns single best match (use `impact --all-matches` for plugin-equivalent behaviour) |
| Trace Site Mapper | `plugins/trace_site_mapper.py` | `reachability --mode trace` | Full | `site_verdict` (valid/site_mismatch/site_unknown) derived from Infoblox extattr Site; AD fallback when Infoblox site data absent |
| Statistics Support | `plugins/stats_support.py` | `stats` (EventBus + StatsManager) | Full | `run_workflow` template publishes `stats:module_detail` events; `cn-lens stats` reads shared aggregated files |
| General Settings | `plugins/general_settings.py` | `config get`, `config set` | Full | `.cn` config management surfaced via config subcommands |
| Config Analyzer | `plugins/config_analyzer_settings.py` | `config diff`, `config find` | Partial | Settings plugin for Config Analyzer TUI not ported; `config diff` + `config find` cover the non-TUI functionality |
