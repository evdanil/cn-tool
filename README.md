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
common network checks.  It is built around a plugin system that allows new
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
script and in the user's home directory.  The `-c` option can point to an
alternative file.  A minimal example looks like:

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

| Key | Description |
| --- | --- |
| `enabled` | Enables the email feature. |
| `send_on_exit` | Send the report automatically when the application exits. |
| `to` | Recipient email address. |
| `server` / `port` | SMTP server and port to connect to. |
| `use_tls` / `use_ssl` | Enable TLS or SSL for the connection. |
| `use_auth` | Authenticate to the SMTP server. |
| `user` / `password` | Credentials used when `use_auth` is true. |

### SD-WAN YAML Search Plugin
Augments configuration search results by scanning a local repository of
SD-WAN YAML files:

| Key | Description |
| --- | --- |
| `enabled` | Enable YAML repository search. |
| `repository_path` | Path to the SD-WAN YAML repository. |


