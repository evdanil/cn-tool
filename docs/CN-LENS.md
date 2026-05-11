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

```bash
cn-lens inspect 10.0.0.1
cn-lens inspect 10.0.0.1 10.0.0.0/24 host.example.net
cn-lens inspect - --format json
cn-lens inspect --file objects.txt --format md
cn-lens inspect --file data.csv --column target --format xlsx --output out.xlsx
```

### `impact`

Find all references to objects across available sources: config repository,
SD-WAN YAML, Infoblox containers, and AD group memberships. Findings are
grouped by source. A `summary["impact"]["matches"]` table is populated for
renderers to emit structured output.

```bash
cn-lens impact 10.1.0.0/24
cn-lens impact SITE01 --format json
cn-lens impact --file prefixes.txt --format xlsx --output impact.xlsx
```

### `dns`

Resolve DNS and Infoblox DNS records for network objects. Performs forward
lookups, reverse (PTR) lookups, and FQDN prefix expansion mirroring the
`fqdn_request` module semantics. Results are collected in
`summary["dns"]` blocks with name→IP and IP→name maps.

```bash
cn-lens dns host.example.net
cn-lens dns 10.0.0.1 --format json
cn-lens dns --file hosts.txt
```

### `reachability`

Perform reachability checks (ping and/or traceroute) for network objects. When
Active Directory is online, traceroute hops are enriched with site codes.
Concurrency is bounded; partial failures are aggregated into findings.

```bash
cn-lens reachability 10.0.0.1
cn-lens reachability 10.0.0.1 --mode trace
cn-lens reachability --file hosts.txt --mode both --format json
```

Flags:
- `--mode ping|trace|both` — probe mode (default: `ping`).

### `device`

Classify and enrich device-oriented network objects by combining AD OU path,
Infoblox host records, and config repository references. Use `--probe` to
additionally test reachability of resolved IPs.

```bash
cn-lens device router1.example.net
cn-lens device router1.example.net --probe
cn-lens device --file devices.txt --format xlsx --output devices.xlsx
```

Flags:
- `--probe` — ping resolved IPs (default: false).

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

### `config find`

Search config repository and SD-WAN YAML for the given query strings. Results
include matched files, line snippets, and per-device match counts.

```bash
cn-lens config find 10.1.0.0/24
cn-lens config find SITE01 --scope cfg --limit 20
cn-lens config find bgp --format json
```

Flags:
- `--scope all|cfg|yaml` — search scope (default: `all`).
- `--limit N` — maximum matches per query.

### `report`

Bundle one or more persisted `LensRun` objects into a `LensReport` aggregate.
Use `--from-last` to include the most recent run, or `--include` to name
specific run IDs. Optionally send the rendered report via the email plugin.

```bash
cn-lens report --from-last
cn-lens report --from-last --format xlsx --output report.xlsx
cn-lens report --include 20260511T120000Z --email ops@example.com
```

Flags:
- `--from-last` — include the most recently persisted run.
- `--include RUN_ID` — add a specific run (repeatable).
- `--email ADDR` — send via email plugin if loaded.

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
- `warnings` — run-level warning strings.
- `errors` — run-level error strings.

## Per-workflow renderer extensions

### Markdown

When a `LensResult` summary contains a workflow-specific key (e.g. `"impact"`,
`"dns"`, `"reachability"`, `"device"`, `"validate_site"`, `"decommission_site"`,
`"allocate"`, `"config_find"`, `"report"`), `render_markdown` emits a fenced
YAML block under a `#### Workflow: <key>` heading instead of inlining the
summary as JSON. This keeps the rendered document readable for complex nested
data.

### xlsx

When any result carries a workflow-specific summary key, `write_xlsx` adds a
`Per-Workflow` sheet with columns `(object, workflow, key, value)`. Each nested
key-value pair under the workflow block becomes a row with the object value in
column A. This sheet is omitted for runs that carry no workflow-specific summary
keys (e.g. plain `inspect` runs).

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
3. A path passed via `-c PATH` on the command line.

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
{"classifier": "ok", "infoblox": "ok", "ad": "ok", "config_repo": "ok", "sdwan_yaml": "ok", "dns": "ok"}
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
| `[ad] enabled`                | device, validate-site, decommission-site, allocate, reachability | Enable AD enrichment. |
| `[ad] uri`                    | Same as above           | LDAP URI for Active Directory. |
| `[cache] enabled`             | All live workflows      | Enable disk-based result cache. |
| `[cache] directory`           | All live workflows      | Cache root directory. |
| `[report] filename`           | report                  | Default output filename for reports. |
| `output_dir`                  | report                  | Root directory for persisted runs (`<output_dir>/cn-lens/<run_id>/run.json.gz`). |
| `site_dns_suffix`             | dns, validate-site      | DNS suffix appended when expanding bare site codes to FQDNs. |

Use `--config PATH` to point at a non-default `.cn` file.

## Exit codes

- `0` — success, with at least one valid object (or for `report`, successful bundle).
- `1` — no valid objects, no input, or no runs available to bundle.
- `2` — usage error, I/O error, or render failure.

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
cn-lens> impact SITE01
cn-lens> dns host.example.net
cn-lens> set format json
cn-lens> report --from-last
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
| `impact <object>`              | Find cross-source references. |
| `dns <object>`                 | Resolve DNS/Infoblox records. |
| `reachability <object>`        | Ping/trace reachability. |
| `device <object>`              | Enrich device objects. |
| `validate-site <site>`         | Validate site consistency. |
| `decommission-site <site>`     | Decommission readiness check. |
| `allocate <prefix>`            | Safety-check prefix allocation. |
| `config find <query>`          | Search config repo / SD-WAN YAML. |
| `report [--from-last] [...]`   | Bundle persisted runs. |
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
