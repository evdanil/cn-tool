# cn-tool documentation

[Project README](../README.md) · [Releases](https://github.com/evdanil/cn-tool/releases)

These guides describe the current source tree. Check `cn --version` before following
instructions for an installed package. The menu and CLI features described here are
available in 0.8.4. The WebUI guide covers changes through this source's 0.9.2,
including the browser tools added in 0.9.0 beyond Subnets that are not part of
0.8.4. Check the installed version before using newer result layouts and navigation.

For a released version, choose its tag in GitHub's branch/tag selector. Releases before
this guide split keep the reference in their README: use the
[0.8.4 reference](https://github.com/evdanil/cn-tool/blob/v0.8.4/README.md) for 0.8.4.
When reading an archive of a later release, use the guides included in that archive.
The package description on PyPI links to these current-source guides; its version
number does not make a `main` link version-specific.

| Task | Guide |
| --- | --- |
| Install, upgrade or configure the first connection | [Installation and first run](installation.md) |
| Use PowerShell, schedule jobs or resolve encoding problems | [Windows](windows.md) |
| Call commands from scripts and interpret results | [Command line](cli.md) |
| Understand Infoblox views, fields, limits and IPv6 | [Infoblox lookup reference](infoblox.md) |
| Check reachability and manage monitoring history | [Ping and monitoring](ping-monitor.md) |
| Set paths, site conventions, cache and report behavior | [Configuration](configuration.md) |
| Configure an Infoblox or device account securely | [Credentials](credentials.md) |
| Add AD, SMTP, YAML or SSH inventory | [Optional integrations](integrations.md) |
| Inspect configuration snapshots and their differences | [Configuration history and browser](config-analyzer.md) |
| Run the optional local browser interface | [WebUI](webui.md) |
| Understand upgrades and previous changes | [Release highlights](release-notes.md) |

Start with ping if you do not use Infoblox. Infoblox lookups require a WAPI endpoint
and an account permitted to read the requested objects. Configuration search and
history tools need readable local repositories. Device inventory needs network and
SSH access; optional integrations need their corresponding services.
