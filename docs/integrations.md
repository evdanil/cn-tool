# Optional integrations

[Documentation](README.md) · [Project README](../README.md)

## Active Directory

Enriches subnet results with Active Directory site information. The account needs read access
to the configured directory search base.

```ini
[ad]
enabled = true
uri = ldap://your-ad-server.example.com
user = domain\user
search_base = CN=Subnets,CN=Sites,CN=Configuration,DC=example,DC=com
connect_on_startup = false
```

## Email

Sends the accumulated Excel workbook on demand or at application exit when configured.
Review the destination and report contents before enabling automatic delivery.

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

## SD-WAN YAML Search

Adds matches from one or more local SD-WAN YAML repositories to menu Configuration
Search. In 0.9.0, WebUI Configuration Search refuses to run when this
integration is enabled; use the menu to include YAML results. WebUI Site Demobilization
uses the menu's core configuration scan and does not include YAML results.
`repository_path` remains a single-repository alias for `repository_paths`.

```ini
[sdwan_yaml_search]
enabled = false
repository_paths = /path/to/repo1,/path/to/repo2
```

## Device inventory and SSH

The device query workflow gathers serial number, software version, image and license data
from Cisco IOS/IOS-XE and NX-OS devices in parallel, with platform autodetection.
It uses the device login from [Credentials](credentials.md), independently of a separate
Infoblox account. `[ssh] config_file` selects an OpenSSH configuration; `ProxyJump`
uses the system SSH client. `[ssh] device_name_filter` can restrict which resolved
hostnames are queried. See the [configuration example](configuration.md).

Bulk DNS Lookup resolves addresses, names and bounded prefixes; IPv6 prefixes are limited
to /112. Bulk Network Trace is available on Linux and macOS when `mtr` is installed;
it is unavailable on Windows. These workflows are available through the interactive menu.
