# cn-tool

<!-- Before a release, review Browser interface and the version scope in docs/README.md,
docs/webui.md and docs/release-notes.md. Promote only verified features from upcoming. -->

Infoblox lookups, network checks and configuration investigation from an interactive
menu or a scriptable command line. cn-tool helps network engineers and system
administrators inspect IP space, check reachability, compare configuration snapshots
and collect device inventory without assembling separate scripts for each task.

It runs on Linux, macOS and Windows 10/11 (x64), with Python 3.10 or newer.
Infoblox is required for IPAM lookups; ping and local configuration tools can run
independently.

## Why use cn-tool with Infoblox?

Grid Manager is useful for administering Infoblox. cn-tool brings common
network-investigation tasks together around your existing Infoblox data:

- **Work through a list:** paste addresses or subnets to see a summary and inspect
  the results, including data from the network views available to your account.
- **Continue the investigation:** combine IPAM lookups with ping, monitoring and
  searches of your local device configurations in one tool.
- **Use results elsewhere:** produce structured command-line output for scripts or
  collect reportable results in an Excel workbook.
- **Choose your interface:** use the local browser interface, interactive menu or
  command line for the workflows each supports.

Infoblox remains the source of IPAM data and enforces the account's permissions.
See [Infoblox access and setup](https://github.com/evdanil/cn-tool/blob/main/docs/infoblox.md#access-and-setup)
for the account and network requirements.

<a id="included-features"></a>

## Features

- **Inspect IPAM and DNS:** look up IPv4/IPv6 addresses, subnets, FQDNs and sites,
  including network views, PTR checks, DHCP data and extensible attributes.
- **Check and monitor reachability:** bulk ICMP and optional TCP probes, repeated
  monitoring, persistent history and summaries of when hosts were seen online.
- **Investigate configurations:** search local repositories, identify snapshot changes
  with `cn diff`, and browse configurations and comparisons in a terminal interface.
- **Collect and enrich results:** query Cisco IOS/IOS-XE and NX-OS inventory, add
  Active Directory subnet information or search local SD-WAN YAML repositories.
- **Reuse the output:** table, JSON, Markdown and CSV output for commands; Excel
  workbooks and optional email delivery for reports.

## Installation

[pipx](https://pipx.pypa.io/) installs cn-tool in its own environment and places its
commands on your PATH:

<a id="from-pypi"></a>

```console
pipx install cn-tool
cn --version
```

Upgrade with `pipx upgrade cn-tool`. In a virtual environment you manage,
`python -m pip install cn-tool` is also supported. `cn-tool` is an alternative name
for `cn` if another installed program already uses that name.

<a id="from-the-zip-or-a-clone"></a>

See [installation and upgrades](https://github.com/evdanil/cn-tool/blob/main/docs/installation.md)
for virtual environments, release archives and source installs, or the
[Windows guide](https://github.com/evdanil/cn-tool/blob/main/docs/windows.md) for PowerShell.

<a id="first-run"></a>

## Quick start

Try a local reachability check without Infoblox or credentials. ICMP needs the system
`ping` command:

```console
cn ping 127.0.0.1
```

For Infoblox, you need an account whose admin group permits API access and has
read access to the relevant data. See [Infoblox access and setup](https://github.com/evdanil/cn-tool/blob/main/docs/infoblox.md#access-and-setup),
then create your user configuration:

```console
cn init
```

This writes `~/.cn` (`%USERPROFILE%\.cn` on Windows) and never overwrites a file.
Open it in a text editor, uncomment `[api]`'s `endpoint`, set your grid's WAPI URL
and save as UTF-8. Then run:

```console
cn doctor
cn
```

`cn doctor` checks configuration and, when configured, the Infoblox connection.
`cn` opens the interactive menu. A terminal can prompt for credentials;
[separate Infoblox accounts and GPG sources](https://github.com/evdanil/cn-tool/blob/main/docs/credentials.md)
are also supported. Edit the configuration in a text editor to keep its comments.

## Command line

Run one command for scripts or individual tasks:

```console
cn ip 10.20.0.5 --format json
cn subnet 10.20.0.0/24 --view prod --format md
cn ping router.example.net --tcp 22,443
cn monitor 10.20.0.0/28 --every 1m --for 2h
cn diff router01 --since 24h
```

Results go to stdout; progress and errors go to stderr. Commands do not prompt
without a terminal. Use `cn --help` or `cn <command> --help` for options, and the
[CLI reference](https://github.com/evdanil/cn-tool/blob/main/docs/cli.md) for input files,
output schemas and exit statuses. Command-line reports require `--report` or `-r FILE`.

<a id="local-subnets-interface"></a><a id="local-subnets-ip-and-ping-interface"></a>

## Browser interface

The optional local browser interface is installed separately:

```console
pipx install "cn-tool[webui]"
cn-web
```

For an existing pipx installation, use `pipx upgrade "cn-tool[webui]"`.
With a regular Python installation, `python -m cn_tool.webui` starts the same interface.
It binds to `127.0.0.1` and uses your existing `.cn` configuration.

**Version scope:** release **0.9.0** provides Subnets, IP, Ping, Monitor,
Configuration Search and Site Demobilization. Release 0.8.4 provides Subnets.
The two configuration scans run on Linux and Windows; on macOS, Site Demobilization
network preview and the other tools remain available. Windows-native verification
for the 0.9.0 additions remains deferred.
See the [WebUI guide](https://github.com/evdanil/cn-tool/blob/main/docs/webui.md) for details.
Closing a tab keeps the application running; **Quit application** ends it and runs
configured exit actions, including email when enabled.

## Documentation

These links describe current source and identify planned features where applicable. For an installed release, check `cn --version`
and use the matching tag; the
[0.8.4 README](https://github.com/evdanil/cn-tool/blob/v0.8.4/README.md) documents that release.
The [documentation index](https://github.com/evdanil/cn-tool/blob/main/docs/README.md)
explains version scope.

| Guide | Details |
| --- | --- |
| <a id="windows"></a><a id="terminal-and-python"></a><a id="passwords-in-powershell"></a><a id="scheduled-tasks"></a><a id="output-and-encoding"></a><a id="files-reports-and-certificates"></a><a id="what-differs-from-linux"></a>[Windows](https://github.com/evdanil/cn-tool/blob/main/docs/windows.md) | PowerShell, encoding, scheduled tasks and platform differences |
| <a id="output"></a><a id="exit-status"></a><a id="json-for-scripts"></a><a id="health-check-cn-doctor"></a>[Command line](https://github.com/evdanil/cn-tool/blob/main/docs/cli.md) | Commands, inputs, output, JSON, statuses and `cn doctor` |
| <a id="ptr-dhcp-utilization-and-child-containers"></a><a id="network-views"></a><a id="ipv6"></a>[Infoblox](https://github.com/evdanil/cn-tool/blob/main/docs/infoblox.md) | API access, setup, lookup behavior, network views and IPv6 |
| <a id="bulk-ping-cn-ping"></a><a id="ping-monitor-cn-monitor"></a>[Ping and monitoring](https://github.com/evdanil/cn-tool/blob/main/docs/ping-monitor.md) | Probe limits, history, reruns and deletion |
| <a id="configuration"></a>[Configuration](https://github.com/evdanil/cn-tool/blob/main/docs/configuration.md) | File precedence, settings, reports and Setup |
| <a id="credentials"></a><a id="gpg-credentials-file"></a><a id="gpg-credentials-file-1"></a><a id="infoblox-account-file"></a>[Credentials](https://github.com/evdanil/cn-tool/blob/main/docs/credentials.md) | Infoblox and device accounts, environment variables and GPG |
| <a id="optional-integrations"></a><a id="active-directory"></a><a id="email"></a><a id="sd-wan-yaml-search"></a>[Integrations](https://github.com/evdanil/cn-tool/blob/main/docs/integrations.md) | AD, email, YAML, device inventory, DNS and trace tools |
| <a id="config-analyzer"></a><a id="configuration-changes-cn-diff"></a>[Configuration history](https://github.com/evdanil/cn-tool/blob/main/docs/config-analyzer.md) | `cn diff`, repository layout and browser TUI keys |
| <a id="whats-new-in-081"></a><a id="whats-new-in-080"></a><a id="whats-new-in-070"></a>[Release highlights](https://github.com/evdanil/cn-tool/blob/main/docs/release-notes.md) | Upgrade notes and links to tagged releases |

<a id="notes"></a>

## Operational notes

Infoblox queries read grid data. Network checks make probes; reports, cache and ping
history write local files. Reports can contain sensitive network information and
accumulate earlier results; review them before downloading or emailing them.
Store credentials through the documented sources and keep TLS verification enabled
with an appropriate CA bundle. See each guide for platform limits and error behavior.

## Project

[Source](https://github.com/evdanil/cn-tool) ·
[Issues](https://github.com/evdanil/cn-tool/issues) ·
[Releases](https://github.com/evdanil/cn-tool/releases) ·
[Apache-2.0 license](https://github.com/evdanil/cn-tool/blob/main/LICENSE)
