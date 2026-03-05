Copyright 2025 - Evgeny Danilchenko evdanil@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# cn-tool

`cn-tool` is a modular network utility that queries Infoblox and performs
common network checks. It is built around a plugin system that allows new
features to be added without modifying the core.

## Features

- IP/Subnet/DNS/Site lookups using the Infoblox API
- Bulk ping, resolve and traceroute operations
- Configuration repository searches for cleanup and validation tasks
- Device information collection (serial number, IOS version and image,
  license data) in parallel
- Disk based cache for faster repeated lookups
- Active Directory enrichment for subnet information
- SD-WAN YAML repository search and Trace Site Mapper plugins
- Saves results to `report.xlsx` and can email the report on exit or on demand
- Configurable logging, color themes and `.cn` configuration file

## Installation and usage

1. git clone https://github.com/cn-tool
2. cd cn-tool
3. Install required python packages (json, rich, pandas, argparse) using command:

```
pip install -r requirements.txt
```

4. Set execute bit on the python script file:

```
chmod +x main.py
```

5. [Optional] To avoid being asked each time executing cn-tool - set up environmental variable `TACACS_PW`, if it is not set - program will request for credential(password). Script uses env['USER'] as login name for devices

```
export TACACS_PW=secret
```

6. [Optional] Add request to read `TACACS_PW` credential during login by adding to `.bash_profile`:

```bash
cat >> ~/.bash_profile <<EOF
echo -n "Enter current TACACS_PW:"
read -s TACACS_PW
export TACACS_PW
EOF
```

7. [Optional] Create alias for convenience by adding line to `.bash_profile`

```bash
cat >> ~/.bash_profile <<EOF
alias cn=/path/to/cn-tool.py
EOF
```

8. Start using this tool using created alias or `cn-tool.py`

```
cn
```

# Configuration

`cn-tool` looks for an ini-style configuration file named `.cn` next to the
script and in the user's home directory. The `-c` option can point to an
alternative file. A minimal example looks like:

```ini
[api]
endpoint = https://infoblox.example.com
verify_ssl = true
timeout = 10

[logging]
logfile = ~/cn.log
level = INFO

[report]
filename = ~/report.xlsx
auto_save = true

[config_repo]
directory = /opt/data/configs

[cache]
directory = ~/.cn-cache
enabled = true

[theme]
name = default
```

### Additional Options (Large Repos / Large Configs)

These options were added to handle bigger repositories, heavy vendor configs
(for example large XML configs), and report write contention.

Note: primary section is `[report]`. For compatibility, `[output]` is also accepted.

#### Report output options

| Section / Key                   | Default | Explanation |
| ------------------------------ | ------- | ----------- |
| `[report] lock_timeout`        | `120`   | Max time (seconds) to wait for report file lock before failing with lock timeout. Increase when multiple tasks/processes write to the same report. |
| `[report] max_config_tab_kb`   | `512`   | Max config size (KB) to include as a full per-device tab in Excel. If exceeded, tool creates a tab with a notice instead of embedding full config text. |

#### Config repository options

| Section / Key                        | Default   | Explanation |
| ----------------------------------- | --------- | ----------- |
| `[config_repo] excluded_dirs`       | *(empty)* | Comma-separated directory names to skip during discovery/indexing (case-insensitive), e.g. `old,history,mobilerouter`. Useful to avoid indexing legacy trees. |
| `[config_repo] history_dir`         | `history` | Folder name treated as snapshot-history path for analyzer workflows and excluded from live config indexing by default. |

#### Cache indexing tuning options

| Section / Key                                  | Default  | Explanation |
| --------------------------------------------- | -------- | ----------- |
| `[cache] check_workers`                        | `4`      | Worker count for "did file change?" checks (mtime/hash). Higher improves pre-check speed but uses more CPU. |
| `[cache] index_workers`                        | `4`      | Worker count used to parse/index configs. Increase gradually; too high can increase contention and memory. |
| `[cache] index_executor`                       | `thread` | Index worker model: `thread` or `process`. Use `process` when GIL is a bottleneck on CPU-heavy parsing. |
| `[cache] index_queue_size`                     | `64`     | Max queued indexing results waiting for cache writer. Larger queue can improve throughput but uses more RAM. |
| `[cache] index_batch_size`                     | `100`    | Number of indexed hosts written per cache transaction. Larger batches reduce write overhead; smaller batches reduce peak memory. |
| `[cache] index_max_positions_per_key`          | `64`     | Cap on stored line positions per indexed key (IP/keyword) per host. Lower value shrinks cache size; higher value improves hit precision. |
| `[cache] index_skip_vendors`                   | *(empty)* | Comma-separated vendors to skip from both keyword and IP indexing (device metadata still tracked). Useful for very large config formats. |
| `[cache] index_skip_keyword_vendors`           | *(empty)* | Vendors to skip only keyword index generation for. |
| `[cache] index_skip_ip_vendors`                | *(empty)* | Vendors to skip only IP index generation for. |
| `[cache] sqlite_cache_size`                    | `16M`    | SQLite page cache per database. Supports K/M/G suffixes (converted to pages, rounded to power of 2) or plain page count. 8 databases total. |
| `[cache] sqlite_mmap_size`                     | `32M`    | SQLite mmap size per database. Supports K/M/G suffixes. Total across 8 databases: 8 × this value. |

Example tuning snippet:

```ini
[config_repo]
excluded_dirs = old,history,mobilerouter

[cache]
check_workers = 8
index_workers = 6
index_executor = process
index_batch_size = 50
index_max_positions_per_key = 32
index_skip_vendors = paloalto
sqlite_cache_size = 16M
sqlite_mmap_size = 32M

[report]
lock_timeout = 180
max_config_tab_kb = 512
```

### Active Directory Plugin

Enable enrichment of subnet data from Active Directory:

```ini
[ad]
enabled = true
uri = ldap://your-ad-server.com
user = domain\user
search_base = CN=Subnets,CN=Sites,CN=Configuration,DC=domain,DC=com
connect_on_startup = true
```

### Email Plugin

The tool can send reports via email using settings in the `[email]` section:

| Key                   | Description                                               |
| --------------------- | --------------------------------------------------------- |
| `enabled`             | Enables the email feature.                                |
| `send_on_exit`        | Send the report automatically when the application exits. |
| `to`                  | Recipient email address.                                  |
| `server` / `port`     | SMTP server and port to connect to.                       |
| `use_tls` / `use_ssl` | Enable TLS or SSL for the connection.                     |
| `use_auth`            | Authenticate to the SMTP server.                          |
| `user` / `password`   | Credentials used when `use_auth` is true.                 |

### SD-WAN YAML Search Plugin

Augments configuration search results by scanning a local repository of
SD-WAN YAML files:

| Key               | Description                         |
| ----------------- | ----------------------------------- |
| `enabled`         | Enable YAML repository search.      |
| `repository_path` | Path to the SD-WAN YAML repository. |

## Config Analyzer (TUI)

The Config Analyzer provides an interactive TUI to browse the configuration repository and compare snapshots.

- Quick filter: start typing to filter devices or snapshots by name/author/date; Backspace/Ctrl+H to edit, Esc to clear.
- Enter: select in snapshot list (toggle up to two to show a diff).
- Tab: switch focus between list and diff (aliases: Tab/Ctrl+I). Shift+Tab cycles backwards.
- Diff actions: D toggles unified/side-by-side; H hides unchanged (only when the diff pane is focused).
- Layout: Ctrl+L cycles right / bottom / left / top. Vertical layouts split the screen evenly.
- Timestamps: shown in UTC (YYYY-MM-DD HH:MM TZ) for consistent comparisons.
- Snapshot dedupe: `Current` is omitted when it's identical to the latest snapshot.

Settings (Setup -> Config Analyzer):

- Analyzer repo directory: overrides the global [config_repo] directory for the TUI only.
- History folder name: subfolder to scan for device snapshots (e.g. `history`).
- Default layout: right/left/top/bottom.
- Scroll to end on load: whether the diff pane auto-scrolls to the bottom.
- Debug logging: enables extra logs in the analyzer.
