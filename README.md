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

# cn-tool.py
Utility allowing to receive information from Infoblox API

## Features modular design with plugin system:
- Performs IP/Subnet/DNS/Site information lookups using Infoblox API
- Integrates with Active Directory
- Performs bulk ping operations
- Performs bulk FQDN/IP lookups using system resolver
- Performs configuration checks across configuration storage (`/opt/data/configs/`) for obsolete configuration when device being removed (cleanups on BGP borders/prefixes/ACLs)
- Obtains device information (serial number, IOS version and image, license data) in parallel
- Saves all requested information for later information processing(by default `report.xlsx` in current directory) 
- Supports email as delivery method for report
- Keeps log of requests/responses(by default `cn.log` in current directory)
- Supports several levels of logging
- Supports ini-style configfile to set logging level/filenames/api endpoint/autosaving(default filename `.cn`)
- Supports several color themes

# How to use
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
