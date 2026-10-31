# Configuration

[Documentation](README.md) · [Project README](../README.md)

`cn-tool` reads ini-style configuration from these files, in this order (a later file overrides an
earlier one):

1. `.cn` in the root of a zip or a clone, next to `main.py` (a pip install has none)
2. `~/.cn` (`%USERPROFILE%\.cn` on Windows), the file `cn init` creates
3. a file passed with `-c`

Save `.cn` as UTF-8; a byte-order mark is fine. A file in another encoding (a Windows ANSI code page
with an accented letter in it) is not read: `cn` logs the parse error and runs on its defaults.
Paths may start with `~`, and on Windows may be drive paths such as `D:\configs`. The log, the
report, the cache, the GPG file and the Ping Monitor's history default to `~/cn.log`,
`~/report.xlsx`, `~/.cn-cache`, `~/cn-tool.gpg` and `~/.cn-ping-history.db`, in your home directory
on every system; the keys below move them.

Example:

```ini
[api]
# the WAPI base URL of your grid, with the WAPI version; the trailing slash is optional
endpoint = https://gm.example.com/wapi/v2.12/
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

[ping]
# The Ping Monitor's history (cn monitor, menu m): one SQLite file per machine
# history_file = ~/.cn-ping-history.db
# Days a recorded round is kept; a run removes older rounds when it starts
# history_days = 30
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

## Reports and setup

Reports are written to `~/report.xlsx` by default. `[report] auto_save` controls automatic
saving in the menu and browser interface. Command-line runs save only with `--report`
or `-r FILE`; see [Output and exit status](cli.md#exit-status).

The Application Setup menu (`s`) edits the user-level `~/.cn` file through `configparser`,
which removes its comments, including comments from `cn init`. Use a text editor to keep them.
Report and GPG settings accept file targets when their parent directory is accessible.
The status block uses configuration-only checks; `cn doctor` adds live Infoblox checks.
A configured network view is validated by a lookup after login, rather than when saved.

Configure credential sources as described in [Credentials](credentials.md).
The `[api]` and `[auth]` sections contain account names or environment-variable names,
not an Infoblox password. Optional SMTP authentication has separate settings in
[Email](integrations.md#email).
