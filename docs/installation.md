# Installation and first run

[Documentation](README.md) · [Project README](../README.md)

## Installation

cn-tool needs Python 3.10 or newer, on Linux, macOS or Windows 10 and 11 (x64). On Windows, Python
3.12 to 3.14 is recommended (see [Windows](windows.md#windows)). The macOS `ping` and `ping6` were run on a real Apple-silicon Mac runner (macOS
26); a silent IPv6 host, Intel Macs and older macOS versions have not been run.

## From PyPI

[pipx](https://pipx.pypa.io/) gives cn-tool a virtual environment of its own and puts its commands
on your PATH. On Windows, `py -m pip install --user pipx`, then `py -m pipx ensurepath` and a new
terminal install pipx itself.

```bash
pipx install cn-tool
cn --version
```

Or install it into a virtual environment you manage:

```bash
python -m venv .venv
source .venv/bin/activate      # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install cn-tool
```

Either way you get the commands `cn` and `cn-tool` (the same program) and `python -m cn_tool`. If
another program on your PATH already provides a `cn` (the npm package of that name does), use
`cn-tool`. Upgrade with `pipx upgrade cn-tool`, or `pip install --upgrade cn-tool`.

## From the zip or a clone

Unpack the zip of a release (or clone the repository), create a virtual environment, and install the
dependencies:

```bash
pip install -r requirements.txt
python main.py
```

`pip install .` installs that source version; it may differ from the version on PyPI. When you upgrade a zip,
unpack it into a new, empty directory: the code lives in a `cn_tool` folder now, and the release
notes of 0.7.0 say what to move.

On a shared server where users cannot write to the install directory, run
`python -m compileall -q /path/to/cn-tool` after each unpack or update, with the Python that runs
`cn`. Python cannot cache compiled modules in a read-only directory, so without this step it
compiles every cn module on every start: about 0.14 s more for a lookup (0.42 s instead of 0.28 s
on a shared dev host, measured with 0.4.1). A pip install compiles its files when it installs.

## First run

```bash
cn init
```

writes a commented starting configuration to `~/.cn` (`%USERPROFILE%\.cn` on Windows). It never
overwrites a file: it exits 2 and changes nothing when `~/.cn` exists. Open the file in a text editor
(`notepad $HOME\.cn` on Windows), remove the `# ` in front of `endpoint` in `[api]` and set your
Infoblox grid, and save the file as UTF-8. Then run:

```bash
cn doctor
```

It checks the configuration, the credentials and the Infoblox WAPI. While no configuration file
exists at all, `cn doctor` (a `Config file` row first), the menu's start-up warning and a refused
command-line lookup tell you to run `cn init`; the `.cn` in the root of a zip or a clone counts as
a configuration file, so only a pip install sees these hints.

Edit `~/.cn` in a text editor, not through the menu's Application Setup (`s`): Setup rewrites the file
without its comments. The rest of the configuration is described in [Configuration](configuration.md#configuration).
