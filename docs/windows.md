# Windows

[Documentation](README.md) · [Project README](../README.md)

cn-tool runs natively on Windows 10 and 11 (x64), in Windows PowerShell 5.1 and in PowerShell 7,
without WSL. The commands on this page are for PowerShell.

## Terminal and Python

- **Terminal.** Windows Terminal is recommended; the older console window works too, though spinner
  glyphs may show as boxes there. In Warp (warp.dev), typed text at a line prompt such as Bulk Ping's
  can be drawn over the line above the cursor; plain PowerShell and the ordinary console are not
  affected, and no cause in `cn` was found (the likely one, a cursor move that Windows' pseudo-console
  sends after the menu's alternate screen, is inferred, not confirmed in Warp): use Windows Terminal or
  PowerShell. The menu needs a real console: the terminal of Git Bash is not
  one, so `cn` alone refuses to open the menu there (`cn: no command given and no terminal for the
  menu`) and exits 2; run `winpty cn`, or use Windows Terminal. A command such as `cn ip 10.1.2.3`
  works anywhere.
- **Python.** Install it from python.org or with the Python install manager; both provide the `py`
  launcher. The Microsoft Store Python works but has no `py`: write `python -m pip` where this page
  says `py -m pip`. Python 3.12 to 3.14 is recommended: Python 3.15 was too new for PyYAML's Windows
  wheel when 0.7.0 was released, so pip would need a compiler there. On Windows on Arm, install the
  x64 Python; cn runs under emulation.
- **When `cn.exe` is blocked** by AppLocker or antivirus (for the web interface and a shortcut, see
  [Starting on a managed Windows PC](#starting-on-a-managed-windows-pc)): `py -m pip install --user cn-tool`, then
  `py -m cn_tool` with the same commands and options (`py -m cn_tool ip 10.1.2.3`). A pipx install
  keeps cn-tool in its own environment, so `py -m cn_tool` finds nothing there.

## Starting on a managed Windows PC

When pip installs cn-tool it writes `cn.exe`, `cn-tool.exe` and `cn-web.exe` on your PC. They are small
launchers that cannot be signed, so application control (AppLocker, WDAC, Smart App Control) or antivirus
may block them. Start cn through Python itself instead, which python.org signs (the shortcut needs cn-tool
0.12.1 or later):

1. Install Python 3.12, 3.13 or 3.14 from python.org.
2. Make an environment in your local profile and install cn-tool into it:

   ```powershell
   py -m venv "$env:LOCALAPPDATA\cn-tool"
   & "$env:LOCALAPPDATA\cn-tool\Scripts\python.exe" -m pip install "cn-tool[webui]"
   ```

   You do not need `Activate.ps1`, which policy often blocks: the full path to `python.exe` works without
   it.
3. Write the shortcut:

   ```powershell
   & "$env:LOCALAPPDATA\cn-tool\Scripts\python.exe" -m cn_tool.webui --create-shortcut
   ```

   It writes **cn-tool Web** to the Start menu and the Desktop. Add `-c "C:\path\team.cn"` for a shortcut
   that opens that configuration, and `--console` for one that keeps a console window.
4. Double-click **cn-tool Web**. The interface opens in your browser with no console window; stop it with
   **Quit application**. Clicking the shortcut again while it runs reopens the same session, so a closed
   tab is never lost.
5. For the menu and the command line, use the same `python.exe` with `-m cn_tool`, for example
   `& "$env:LOCALAPPDATA\cn-tool\Scripts\python.exe" -m cn_tool ip 10.1.2.3`.

Good to know:

- **What the policies check.** AppLocker and WDAC check the program a shortcut starts (here the signed
  `pythonw.exe`), not the shortcut itself; WDAC also checks every library (`.pyd`) Python loads. The
  default AppLocker rules allow programs under Program Files and Windows only, so a Python or environment in
  your profile may need a publisher rule for "Python Software Foundation" from your administrator. When a
  library is blocked, cn-tool says "A part of the web interface could not be loaded" and names it.
- **Nothing happens on a double-click?** Run the command of step 3 without `--create-shortcut` in
  PowerShell to see the error.
- **After upgrading or reinstalling Python**, or moving the environment, run step 3 again: the shortcut
  points at that `python.exe`.
- **A Desktop in OneDrive** syncs the shortcut to your other PCs, where it may not work; delete it there.
- **Write the shortcut as the user who will use it**, not from a separate administrator account, which
  would put it in that account's profile.
- **pipx** works the same way through Python: `py -m pipx install "cn-tool[webui]"` (`pipx.exe` is a
  launcher too).

## WebUI dependency compatibility (0.10.0)

The Windows `webui` extra pins Pydantic to 2.14.2, which selects
`pydantic-core==2.50.2`. This pair worked on a Python 3.12 x64 workstation where
application control blocked `_pydantic_core.cp312-win_amd64.pyd` from core 2.50.4.
The pin does not change Windows policy or guarantee approval on another machine.
It does not affect base installs or the Linux/macOS web UI dependencies.

If Windows reports that an Application Control policy blocked a `.pyd` file,
ask your administrator to inspect the corresponding CodeIntegrity event and
approve the required binaries. PowerShell's `RemoteSigned` setting governs
scripts and does not resolve a native-extension policy block. Downgrading cn-tool
alone does not restore the earlier transitive dependency versions.

## Passwords in PowerShell

PowerShell's PSReadLine saves your command lines in plain text in
`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, except lines that
contain words such as `password` or `secret`. So never type `$env:TACACS_PW = 'secret'`. For one
terminal, without leaving the password in the history file:

```powershell
$env:TACACS_PW = Read-Host 'TACACS password' -MaskInput
```

(PowerShell 7.1 and later), or, in Windows PowerShell 5.1, which has no `-MaskInput`:

```powershell
$env:TACACS_PW = [Net.NetworkCredential]::new('', (Read-Host 'TACACS password' -AsSecureString)).Password
```

Or leave it unset: `cn` asks, without echo, when it needs it. `setx TACACS_PW …` is worse:
- it stores the password in plain text in the registry (`HKCU\Environment`);
- every program you start later can read it;
- it roams with a roaming profile;
- the terminal you typed it in does not see it.

Use `setx` for names only (`setx INFOBLOX_USER svc-ipam`). Remove a stored password with
`[Environment]::SetEnvironmentVariable('TACACS_PW', $null, 'User')`. The same holds for
`INFOBLOX_PW`.

The device login's user name is read from `USERNAME` (Windows has no `USER`). If your device login
is not your Windows user name, put it in a variable of your own (`setx CN_USER alice`, a name is
not a secret) and name that variable in `.cn`:

```ini
[auth]
device_user_var = CN_USER
```

## Scheduled tasks

A Task Scheduler task sees only the environment that is stored for its account, and it cannot show
gpg's passphrase window: gpg waits out its 90 second timeout, and a device GPG file older than 24
hours is ignored. Keep the password with DPAPI, which only your account on that computer can read:
once, in a normal PowerShell session,

```powershell
Read-Host 'TACACS password' -AsSecureString | ConvertFrom-SecureString | Set-Content $HOME\.cn-tacacs
```

and in the task's script, before `cn`:

```powershell
$env:TACACS_PW = [Net.NetworkCredential]::new('', (Get-Content $HOME\.cn-tacacs | ConvertTo-SecureString)).Password
```

To save text from a task, redirect through `cmd`: `cmd /c "cn ping 10.1.2.0/24 --format csv > out.csv"`
(see [Output and encoding](#output-and-encoding)).

## GPG credentials file

Install [Gpg4win](https://www.gpg4win.org/) for `-g` and `[gpg]` files, and open a new terminal so
that `gpg` is on the PATH; without it `cn` says `gpg is not installed (install Gpg4win, then open a
new terminal)`. gpg-agent asks for the key's passphrase in Gpg4win's window. Make the credentials
file in an editor such as Notepad, saved as UTF-8, encrypt it, and delete the plain copy:

```powershell
notepad $HOME\cn-tool-credentials.txt     # two lines: User = alice and Password = ...
gpg --encrypt --recipient YOUR_KEY_ID --output $HOME\cn-tool.gpg $HOME\cn-tool-credentials.txt
Remove-Item $HOME\cn-tool-credentials.txt
```

One way of writing the file fails in Windows PowerShell 5.1: `>` and a plain `Out-File` write UTF-16,
and `cn` then says the file `could not be decrypted by gpg --batch`. Notepad, `Set-Content -Encoding
utf8`, `Out-File -Encoding utf8` and `[IO.File]::WriteAllText($path, $text)` write UTF-8, and so do
`>`, `Out-File` and `Set-Content` in PowerShell 7. A byte-order mark at the start of the file, which
Windows PowerShell 5.1 adds to `-Encoding utf8` output, is dropped when `cn` reads the decrypted text.

## Output and encoding

`cn` writes UTF-8 on Windows, also when its output is redirected or piped. PowerShell (5.1 and 7)
decodes a program's output with the console's code page (`[Console]::OutputEncoding`, the OEM code
page: 850 or 437, for example), so a name such as `Zürich` comes out garbled in
`cn … | ConvertFrom-Json` until you run `[Console]::OutputEncoding = [Text.UTF8Encoding]::new()`
(put it in your `$PROFILE` to keep it). Windows PowerShell 5.1 also writes `>` redirections as
UTF-16, which other tools may not read: let `cmd` redirect instead (`cmd /c "cn doctor > out.txt"`
writes UTF-8; PowerShell 7's `>` writes UTF-8 too). Save `.cn` as UTF-8 as well (see
[Configuration](configuration.md#configuration)). The tables use box-drawing characters, so whatever reads them
must read UTF-8.

## Files, reports and certificates

- **Where files go.** `C:\Users\<you>\.cn`, `cn.log`, `report.xlsx`, `.cn-ping-history.db` and the
  `.cn-cache` folder sit in your profile folder, which OneDrive does not sync. The keys move them;
  on a roaming profile, `[cache] directory = ~/AppData/Local/cn-tool/cache` keeps the cache off the
  network. `pipx uninstall cn-tool` leaves these files behind.
- **A report open in Excel.** Excel locks a workbook it has open, so a lookup cannot save to it.
  `cn` says `Error: Could not write the report: C:\Users\alice\report.xlsx is open in another
  program (Excel?). This result is not in the report; close the file before the next lookup.` The
  result is dropped, not retried, and a command-line run exits 3.
- **Certificates.** `requests` trusts the certificate bundle that ships with it, not the Windows
  certificate store. Behind a proxy that inspects TLS, point `REQUESTS_CA_BUNDLE` at your
  organisation's CA bundle (`$env:REQUESTS_CA_BUNDLE = 'C:\certs\corp-ca.pem'`), or turn off
  `[api] verify_ssl` (which disables the check).
- **SSH to devices.** A bastion named by `ProxyJump` in `~\.ssh\config` runs Windows' OpenSSH client
  (`ssh.exe`), which Windows 10 and 11 include as an optional feature.

## What differs from Linux

- Bulk PING runs Windows' own `ping` (see [Bulk ping](ping-monitor.md#bulk-ping-cn-ping)). An IPv6 target that this
  computer has no route to reads `NO RESPONSE`, not `NO ROUTE`.
- The Ping Monitor (see [Ping monitor](ping-monitor.md#ping-monitor-cn-monitor)): closing the window leaves the
  run `lost`, not `stopped`, because Windows sends no SIGTERM or SIGHUP to end it cleanly; its
  finished rounds are kept. Windows prints an IPv6 ICMP error without its sender, so an IPv6 target
  is only ever `!` or `.` there.
- Bulk Network Trace (menu item `t`) is not available: it needs `mtr`, which does not exist on
  Windows. `cn` says `Bulk Network Trace needs mtr, which is not available on Windows.` and returns
  to the menu.
- On Python before 3.14, Windows may not interrupt a bulk run that is waiting for its probes (a
  Python limitation that 3.14 fixes). If Ctrl-C does not stop it, close the window, or use Python
  3.14.
- On the command line, give a file of objects with `--file`, not `< file`: PowerShell reserves `<`.
