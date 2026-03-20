# cn-tool

`cn-tool` is a modular network utility for Infoblox lookups, bulk network
checks, configuration repository searches, and device inventory collection.

## Included Features

- IP, subnet, FQDN, and location lookups using the Infoblox API
- Bulk ping, resolve, and traceroute operations
- Configuration repository search with optional SD-WAN YAML enrichment
- Device inventory queries in parallel
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

The repository browser TUI can be launched either from the menu or directly:

```bash
python -m config_analyzer --repo-path /path/to/repoA --repo-path /path/to/repoB
```

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
