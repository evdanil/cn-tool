# Credentials

[Documentation](README.md) · [Project README](../README.md)

`cn` logs in as `$USER` with `$TACACS_PW` (on Windows the user name is `%USERNAME%`, which is the
default of the `[auth]` setting `device_user_var`); if the password is not set, a GPG credentials
file younger than 24 hours is used (see [GPG Credentials File](#gpg-credentials-file)). Without a terminal `cn` never
prompts: it exits 3 at once with a message that names `TACACS_PW` and the GPG file, so cron jobs
and `ssh host cn …` cannot hang. `cn doctor` shows which source applies and whether the login
works. On Windows, set the password for one terminal as described under [Windows](windows.md#windows).

Infoblox can log in with an account of its own, for example a read-only service account, while
devices and Active Directory keep the TACACS login. Four settings give it: `INFOBLOX_USER` (the
user name; it wins over `[api] user`), `INFOBLOX_PW` (the password), `[api] user` in `.cn` (the user
name only: `.cn` holds no Infoblox password) and `[gpg] infoblox_credentials` (a GPG file, see
below). The password comes from `INFOBLOX_PW`, else the Infoblox GPG file, else a prompt; the user
name from `INFOBLOX_USER`, else `[api] user`, else the GPG file's `User =` line. `$USER` is never
used as the Infoblox user name.

Once any of them is set, Infoblox never uses the TACACS login: a missing half is asked for on a
terminal, and without one `cn` exits 3 and names it, with the reason when a GPG file could not be
used (`cn: no Infoblox password for svc-ipam: set INFOBLOX_PW, or [gpg] infoblox_credentials`). A
GPG file for a different user than `INFOBLOX_USER` or `[api] user` stops the run before anything is
sent. `[api] user` in `.cn` with `INFOBLOX_PW` exported is the setup to start with:

```ini
[api]
user = svc-ipam
```

```bash
read -rs -p 'Infoblox password: ' INFOBLOX_PW; echo; export INFOBLOX_PW
cn ip 10.20.0.5
```

The `.cn` keys apply to every `cn` run of that user, cron jobs included: once `[api] user` is set,
a job without `INFOBLOX_PW` or the GPG file exits 3. Give the job one of them, or keep it on the
TACACS login with `cn -c ~/.cn-tacacs …`, where `~/.cn-tacacs` sets to empty every Infoblox
setting your `~/.cn` has: `[api]` / `user =`, `[gpg]` / `infoblox_credentials =`, and `[auth]` /
`infoblox_user_var =` and `infoblox_password_var =` (empty means `INFOBLOX_USER` and `INFOBLOX_PW`,
which the job does not export). `-c` adds a layer on top of `~/.cn`, so the empty values override
it, while a file that merely lacks the keys would change nothing.

`cn` does not read `INFOBLOX_USERNAME` or `INFOBLOX_PASSWORD`, the names the Terraform provider and
the Ansible NIOS modules use, unless `[auth]` names them (below). An automation account exported
for those tools is never used by accident; `cn doctor` shows which login applies.

When the grid refuses the account's login, `cn` says so with the user and the source of the
password (`Infoblox refused user 'svc-ipam' (password from INFOBLOX_PW).`), sends an account's
first request alone and, after a refusal, nothing more as that account for the rest of the run: a
wrong password costs one refused login per run. A cron job still costs one per run, so act on exit
3 before the grid's lockout (if enabled) locks the account.

The names of the four variables are configurable in `[auth]`: `device_user_var` (default `USER`, and
`USERNAME` on Windows), `device_password_var` (`TACACS_PW`), `infoblox_user_var` (`INFOBLOX_USER`) and
`infoblox_password_var` (`INFOBLOX_PW`). The section holds names, never passwords. A blank value
means the default, and a value that is not a variable name stops the login with exit 2 and the
key's name. When `cn` says where a value came from, it names the variable (`password from
INFOBLOX_PASSWORD`). When it asks you to set a variable that is not set, it names the `[auth]` key
instead (`set the variable named in [auth] infoblox_password_var`): `cn` cannot tell a variable
name from a password typed there by mistake, so it prints a custom name only once that variable
exists. To use the account the Terraform provider and the Ansible NIOS modules read, say so in two
lines:

```ini
[auth]
infoblox_user_var = INFOBLOX_USERNAME
infoblox_password_var = INFOBLOX_PASSWORD
```

`cn` then logs in with whatever those tools use, write rights included (`cn` itself only reads).
The names are read when `cn` logs in: edit `.cn` and restart `cn`.

## GPG Credentials File

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
- The decrypted text must be UTF-8 (a byte-order mark at the start is dropped). On Windows, `gpg`
  comes from Gpg4win, and PowerShell 5.1's `>` writes UTF-16, which is not read: see
  [Windows](windows.md#windows).
- If you do not want to use GPG, set `TACACS_PW` or enter the credential interactively.

#### Infoblox account file

Infoblox's own account (described above) can have a file of its own: point
`[gpg] infoblox_credentials` at it. It has the same two lines (`User =` and `Password =`) but, unlike
the file above, no age limit; recreate it when the password changes. One way to create it, without
writing anything plain to disk:

```bash
read -rs -p 'Infoblox password: ' pw; echo
printf 'User = %s\nPassword = %s\n' svc-ipam "$pw" |
  gpg --yes --encrypt --recipient YOUR_KEY_ID --output ~/infoblox.gpg
unset pw
chmod 600 ~/infoblox.gpg
```

`printf` is a shell builtin, so the password never appears in the process list, and `--yes` lets the
same command replace the file when the password changes. A cron job decrypts with `gpg --batch`, so
it needs a key that gpg can use without asking: a passphrase cached in gpg-agent, or a key kept for
this purpose.
