#!/usr/bin/env python
# Copyright 2024 - Evgeny Danilchenko evdanil@gmail.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import ipaddress
import signal
import json
import sys
import termios
import tty
from itertools import cycle
# from operator import itemgetter
from time import perf_counter
from socket import gaierror, herror, timeout, gethostbyaddr
import socket
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import re
import configparser
from argparse import RawTextHelpFormatter
import argparse
import logging
import pandas as pd
import requests
from requests.exceptions import HTTPError, Timeout, RequestException, MissingSchema
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from rich.console import Console, Group
from rich.table import Table
from rich import box
from rich.style import Style
from rich.panel import Panel
from rich.theme import Theme
import subprocess
from subprocess import Popen, DEVNULL, STDOUT
from datetime import datetime, timedelta
from diskcache import FanoutCache, JSONDisk
from queue import Queue
import threading
from time import time
from netmiko import ConnLogOnly

# Fix MAC address emoji issue
from rich._emoji_codes import EMOJI

del EMOJI["cd"]

MIN_INPUT_LEN = 5
version = '0.1.116 hash 12db1b6'

# increment cache_version during release if indexes or structures changed and rebuild of the cache is required
cache_version = 2

# Disable SSL self-signed cert warnings, comment out line below if Infoblox
# deployment uses proper certificate
urllib3.disable_warnings()

# Adding another thread to save data into xlsx in the background
save_queue = Queue()
save_lock = threading.Lock()
worker_thread = None


class ThreadSafeFileHandler(logging.FileHandler):
    def __init__(self, filename, mode='a', encoding=None, delay=False):
        super().__init__(filename, mode, encoding, delay)
        self._lock = threading.Lock()

    def emit(self, record):
        with self._lock:
            super().emit(record)


COLOR_SCHEMES = {
    "default": {
        "title": "bold #FF69B4",  # Hot Pink
        "header": "bold #00CED1",  # Dark Turquoise
        "hostname": "#20B2AA",  # Light Sea Green
        "sn": "#32CD32",  # Lime Green
        "type": "#4169E1",  # Royal Blue
        "pid": "#FFD700",  # Gold
        "status": "#DA70D6",  # Orchid
        "date": "#40E0D0",  # Turquoise
        "export": "#FF6347",  # Tomato
        "code": "#3CB371",  # Medium Sea Green
        "license_name": "#1E90FF",  # Dodger Blue
        "license_full": "#00FFFF",  # Cyan
        "description": "#F0E68C",  # Khaki
        "reserved": "#DDA0DD",  # Plum
        "enforcement": "#DC143C",  # Crimson
        "auth_type": "#2E8B57",  # Sea Green
        "license_type": "#4682B4",  # Steel Blue
        "start_date": "#5F9EA0",  # Cadet Blue
        "end_date": "#BDB76B",  # Dark Khaki
        "term_count": "#BA55D3",  # Medium Orchid
        "license": "#228B22",  # Forest Green
        "tag": "#DAA520",  # Goldenrod
        "count": "#0000CD",  # Medium Blue
        "feature": "#48D1CC",  # Medium Turquoise
        "value": "#F4A460",  # Sandy Brown
        "success": "#2E8B57",  # Sea Green
        "warning": "#FFA500",  # Orange
        "error": "#B22222",  # Firebrick
        "info": "#4682B4",  # Steel Blue
        "default": "#D2691E",  # Chocolate
        "red": "#DC143C",  # Crimson
        "green": "#228B22",  # Forest Green
        "yellow": "#FFD700",  # Gold
        "blue": "#4169E1",  # Royal Blue
        "magenta": "#FF00FF",  # Magenta
        "cyan": "#00CED1",  # Dark Turquoise
        "white": "#F0F8FF",  # Alice Blue
        "bold": "bold"
    },
    "monochrome": {
        "title": "bold #FFFFFF",  # Pure White
        "header": "bold #E0E0E0",  # Light Gray
        "hostname": "#D3D3D3",  # Light Gray
        "sn": "#C0C0C0",  # Silver
        "type": "#A9A9A9",  # Dark Gray
        "pid": "#DCDCDC",  # Gainsboro
        "status": "#F5F5F5",  # White Smoke
        "date": "#E8E8E8",
        "export": "#B8B8B8",
        "code": "#D9D9D9",
        "license_name": "#CFCFCF",
        "license_full": "#EBEBEB",
        "description": "#C8C8C8",
        "reserved": "#DBDBDB",
        "enforcement": "#BDBDBD",
        "auth_type": "#DEDEDE",
        "license_type": "#E3E3E3",
        "start_date": "#F0F0F0",
        "end_date": "#F8F8F8",
        "term_count": "#E6E6E6",
        "license": "#D6D6D6",
        "tag": "#CCCCCC",
        "count": "#EFEFEF",
        "feature": "#FAFAFA",
        "value": "#F2F2F2",
        "success": "#EAEAEA",
        "warning": "#DFDFDF",
        "error": "#C6C6C6",
        "info": "#EDEDED",
        "default": "#D0D0D0",
        "red": "#B0B0B0",
        "green": "#BEBEBE",
        "yellow": "#CDCDCD",
        "blue": "#DADADA",
        "magenta": "#E9E9E9",
        "cyan": "#F7F7F7",
        "white": "#FFFFFF",  # Pure White
        "bold": "bold"
    },
    "pastel": {
        "title": "bold #87CEFA",  # Light Sky Blue
        "header": "bold #98FB98",  # Pale Green
        "hostname": "#DDA0DD",  # Plum
        "sn": "#90EE90",  # Light Green
        "type": "#ADD8E6",  # Light Blue
        "pid": "#F0E68C",  # Khaki
        "status": "#E0FFFF",  # Light Cyan
        "date": "#FFB6C1",  # Light Pink
        "export": "#FFA07A",  # Light Salmon
        "code": "#98FB98",  # Pale Green
        "license_name": "#87CEFA",  # Light Sky Blue
        "license_full": "#E0FFFF",  # Light Cyan
        "description": "#FAFAD2",  # Light Goldenrod Yellow
        "reserved": "#D8BFD8",  # Thistle
        "enforcement": "#FFA07A",  # Light Salmon
        "auth_type": "#90EE90",  # Light Green
        "license_type": "#ADD8E6",  # Light Blue
        "start_date": "#AFEEEE",  # Pale Turquoise
        "end_date": "#FFFACD",  # Lemon Chiffon
        "term_count": "#DDA0DD",  # Plum
        "license": "#98FB98",  # Pale Green
        "tag": "#F0E68C",  # Khaki
        "count": "#ADD8E6",  # Light Blue
        "feature": "#E0FFFF",  # Light Cyan
        "value": "#FFF5EE",  # Seashell
        "success": "#90EE90",  # Light Green
        "warning": "#FAFAD2",  # Light Goldenrod Yellow
        "error": "#FFA07A",  # Light Salmon
        "info": "#E6E6FA",  # Lavender
        "default": "#FFF5EE",  # Seashell
        "red": "#FFA07A",  # Light Salmon
        "green": "#98FB98",  # Pale Green
        "yellow": "#F0E68C",  # Khaki
        "blue": "#ADD8E6",  # Light Blue
        "magenta": "#DDA0DD",  # Plum
        "cyan": "#E0FFFF",  # Light Cyan
        "white": "#FFF5EE",  # Seashell
        "bold": "bold"
    },
    "dark": {
        "title": "bold #E0FFFF",  # Light Cyan
        "header": "bold #00CED1",  # Dark Turquoise
        "hostname": "#20B2AA",  # Light Sea Green
        "sn": "#32CD32",  # Lime Green
        "type": "#4169E1",  # Royal Blue
        "pid": "#DAA520",  # Goldenrod
        "status": "#9370DB",  # Medium Purple
        "date": "#40E0D0",  # Turquoise
        "export": "#B22222",  # Firebrick
        "code": "#2E8B57",  # Sea Green
        "license_name": "#4682B4",  # Steel Blue
        "license_full": "#008B8B",  # Dark Cyan
        "description": "#CD853F",  # Peru
        "reserved": "#8A2BE2",  # Blue Violet
        "enforcement": "#8B0000",  # Dark Red
        "auth_type": "#006400",  # Dark Green
        "license_type": "#00008B",  # Dark Blue
        "start_date": "#008080",  # Teal
        "end_date": "#BDB76B",  # Dark Khaki
        "term_count": "#9932CC",  # Dark Orchid
        "license": "#228B22",  # Forest Green
        "tag": "#B8860B",  # Dark Goldenrod
        "count": "#0000CD",  # Medium Blue
        "feature": "#20B2AA",  # Light Sea Green
        "value": "#A9A9A9",  # Dark Gray
        "success": "#3CB371",  # Medium Sea Green
        "warning": "#FF8C00",  # Dark Orange
        "error": "#DC143C",  # Crimson
        "info": "#4682B4",  # Steel Blue
        "default": "#D2691E",  # Chocolate
        "red": "#B22222",  # Firebrick
        "green": "#228B22",  # Forest Green
        "yellow": "#DAA520",  # Goldenrod
        "blue": "#4169E1",  # Royal Blue
        "magenta": "#8A2BE2",  # Blue Violet
        "cyan": "#008B8B",  # Dark Cyan
        "white": "#D3D3D3",  # Light Gray
        "bold": "bold"
    }
}

stop_words = {
    "bluecoat": (
        '"',
        "!",
        "max-bandwidth",
        "exit",
        "priority",
        "disable",
        "interface",
        "reject",
        "failover",
        "clear",
        "ssl",
        "inline",
        "-",
        "*",
        "ssh",
        "security hashed-",
        "security windows",
        "group-cache",
        "security radius",
        "alternate-server encrypted-secret",
        "archive-configuration encrypted-",
        "security sequence",
        "security management",
        "access-log",
        "overflow-policy",
        "type",
        "no ",
        "format-name",
        "ftp-client",
        "scp-client",
        "edit log",
        "create log",
        "continuous-upload",
        "upload-settings",
        "service-info",
        "diagnostics",
        "caching",
        "max-cache-size",
        "tunnel",
        "adn",
        "cifs",
        "remote-storage-",
        "mapi",
        "keep-alive",
        "forwarding",
        "load-balance",
        "host-affinity",
        "failure-mode",
        "content-filter",
        "bluecoat",
        "data-source",
        "download",
        "cpu-monitor",
        "event-log",
        "level",
        "syslog en",
        "syslog fa",
        "smtp",
        "http",
        "remove",
        "management-services",
        "force-bypass",
        "proxy-services",
        "delete",
        "attribute",
        "alert",
        "im http",
        "ntp clear",
        "restart",
        "snmp",
        "authentication",
        "privacy",
        "tcp-ip",
        "policy hmac",
        "upgrade-path",
        "default",
        "license-key",
        "statistics-export",
        "ssl-device-profile",
        "inline",
        "(",
        "<",
        "$",
        ")",
        "Click",
        "if",
        "{",
        "}",
        "document.",
        "//",
        "function",
        "var",
        "pin.",
        "return",
        "cookie",
        "else",
        "challenge",
        "realm",
        "rsacompare",
        "isrsarealm",
        "beginlocation",
        "define",
        "end",
        "name=",
        "single=",
        "type=",
        "n=",
        "d=",
        "h=",
        "f-o=",
        "port=",
        "n-",
        "cmt=",
        "t=",
        "typ=",
        "delimiters=",
        "group-",
        "restrict=",
        "suffix=",
        "layertype=",
        "id=",
        "col=",
        "negate=",
        "disabled=",
        "num=",
        "&lt",
        "hashed-",
        'group add "readonly"',
        "line-vty",
    ),
    "f5": (
        "#",
        "cli",
        "update",
        "apm",
        "report",
        "user",
        "auth",
        "role-",
        "/",
        "console",
        "line",
        "role",
        "default-",
        "fallback",
        "type",
        "account",
        "protocol",
        "secret",
        "service",
        "encrypted-p",
        "partition",
        "all-",
        "session-",
        "shell",
        "alias-",
        "prompt",
        "suppress-",
        "cm",
        "cache-",
        "cert",
        "--",
        "checksum",
        "revision",
        "active-mo",
        "build",
        "edition",
        "key",
        "marketing-name",
        "multicast-interface",
        "multicast-port",
        "optional-",
        "product",
        "platform-id",
        "self-device",
        "time-",
        "unicast-address",
        "effective-ip management-ip",
        "effective-port",
        "ip management-ip",
        "multicast-ip",
        "hidden",
        "type",
        "network-failover",
        "unit-id",
        "ca-",
        "status",
        "trust-group",
        "gtm",
        "ilx global-settings",
        "addresses none",
        "debug-port-blacklist",
        "rule none",
        "members",
        "load-balancing-mode",
        "ip-protocol tcp",
        "profiles",
        "mask",
        "rules",
        "source 0.0.0.0/0",
        "source-address-",
        "translate-port",
        "translate-address enabled",
        "creation-time",
        "last-modified-time",
        "persist",
        "default yes",
        "arp",
        "icmp-echo",
        "adaptive",
        "defaults-from",
        "destination *.",
        "interval",
        "ip-dscp",
        "recv",
        "send",
        "time-until-up",
        "timeout",
        "app-service",
        "net port-list",
        "id",
        "vlan",
        "net self-allow",
        "defaults",
        "igmp",
        "ospf",
        "pim",
        "tcp",
        "udp",
        "interfaces",
        "trunks",
        "net stp",
        "net trunk HA",
        "lacp ",
        "tag",
        "net fdb",
        "net ipsec",
        "pem ",
        "security device",
        "id ",
        "action",
        "ip-protocol",
        "sys",
        "inherited-",
        "gui-",
        "request-options",
        "bfd-",
        "flooding-type",
        "log-level",
        "logical-",
        "tunnel-maintenance-mode",
        "network default",
        "level nominal",
        "agent-addresses",
        "communities",
        "disk-monitors",
        "minspace",
        "max-processes",
        "process",
        "snmpv",
        "privacy-",
        "version",
        "expiration",
        "options",
        "password",
        "development-mode",
        "property-",
        "availability-",
        "valid-values",
        "instance-type",
        "region",
        "dhcp-",
        "node-",
        "cloud-",
        "auto-",
        "end-",
        "frequency",
        "wom",
    ),
    "aruba": (
        "interface",
        "switchport",
        "spanning",
        "key",
        "netservice",
        "priority-map",
        "queue-weights",
        "ap-console-password",
        "bkup-passwords",
        "g-",
        "a-",
        "wmm",
        "qbss-",
        '"',
        "band-",
        "regulatory-domain",
        'id "',
        "airgroupprofile",
        "logging level",
        "logging security",
        "snmp-server trap",
        "conductor-l3redundancy",
        "l3-sync",
        "ip nat",
        "permit any",
        "netservice svc-",
        "netdestination6 ipv6-reserved-range",
        "invert",
        "netexthdr",
        "time-range",
        "weekday",
        "user",
        "any any svc-",
        "ipv6 any any",
        "network 127.",
        "network 169.254.",
        "network 224.0.0",
        "host 255.255.255.255",
        "network 240.0.0.0",
        "any any any permit",
        "ipv6 host fe80",
        "ipv6 network fc00",
        "ipv6 network fe80",
        "ipv6 alias ipv6-reserved-range",
        "ipv6 any any any",
        "any any app alg-",
        "any any svc-",
        "ipv6 any any svc-",
        "ipv6 any any svc-v6-dhcp permit",
        "ip access-list session captiveportal",
        "any any tcp",
        "any any udp",
        "any any ip",
        "no ",
        "vpn-dialer",
        "ike authentication",
        "aaa tacacs",
        "command ",
        "controller-ip vlan",
        "datapath",
        "kernel coredump",
        "interface mgmt",
        "shutdown",
        "vlan ",
        "trusted",
        "ip nexthop",
        "crypto ",
        "version",
        "encryption",
        "hash",
        "authentication",
        "group",
        "prf",
        "set transform-set",
        "localip 0.0.0.0 ipsec",
        "vpdn",
        "ip dynamic-dns",
        "snmp-server",
        "tunneled-node-address",
        "adp",
        "ap",
        "amon",
        "ssh mgmt-",
        "mgmt-user ",
        "ip mobile",
        "ip igmp",
        "ipv6 mld",
        "firewall",
        "prohibit-ip-spoofing",
        "attack-rate",
        "session-idle-timeout",
        "cp-",
        "amsdu",
        "wireless-",
        "session-tunnel-fib",
        "optimize-dad-frames",
        "deny-needfrag-df-ipsec",
        "ipv6 firewall",
        "ext-hdr-parse-len",
        "dpi-classif-cache",
        "ipv4 permit any proto 6",
        "ipv6 permit any proto 6",
        "ipv6 deny any proto",
        "ip domain",
        "country",
        "change-config-node",
        "key ",
        "session-authorization",
        "aaa authentication via",
        "scheduler-profile",
        "queue-weights",
        "priority-map",
        "authentication-mac",
        "mac-default-role",
        "initial-role",
        "enable",
        "web-",
        "guest-",
        "ids",
        "control-plane-security",
        "aaa policy",
        "valid-network",
        "traceoptions",
        "activate",
        "file ",
        "ucc",
        "license-",
        "pefng-",
        "rfp-",
        "papi-security",
        "est profile",
        "aruba-central",
        "ifmap cppm",
        "pan",
        "banner",
        "virtual-ap",
        "websocket",
        "openflow",
        "sdwan-profile",
        "valid-",
        "gps",
        "channel-",
        "node-",
        "frame-type",
        "dst-mac",
        "src-mac",
        "bssid valid-ap",
        "payload",
        "rf",
        "arm-",
        "wlan hotspot",
        "wpa-passphrase",
        "opmode",
        "mcast-rate-opt",
        "band-steering",
        "dynamic-mcast-optimization",
        "broadcast-filter",
        "stats-enable",
        "tag-enable",
        "sessions-enable",
        "monitored-",
        "wids-",
        "misc-",
        "location-e",
        "uccmonitoring-",
        "airgroupinfo-",
        "wan-state",
        "sessions-enable",
        "airmatch",
        "condition",
        "enet",
        'id "',
        'service "',
        "logging security",
        "process",
        "ale-configuration",
    ),
    "cisco": (
        "!",
        "*",
        "^C",
        "#",
        "end",
        "Building",
        "timers",
        "ip bgp-community new-format",
        "route-map bgp_to_ospf",
        "Current",
        "boot",
        "vrf definition mgmtVrf",
        "address-family ",
        "exit-address-family",
        "mac-address ",
        "rd ",
        "route-target ",
        "ip multicast",
        "service-policy",
        "power redundancy",
        "mac access-list",
        "redundancy",
        "mode",
        "lldp",
        "priority",
        "police",
        "dbl",
        "speed ",
        "duplex ",
        "dual-active",
        "ip vrf forwarding",
        "ip ospf authentication",
        "ip ospf message-digest-key",
        "passive-interface",
        "logging buffered",
        "logging monitor",
        "logging trap",
        "logging origin",
        "logging source",
        "username",
        "redistribute",
        "bgp log",
        "permit tcp any any",
        "permit udp any any",
        "deny ipv6 any any",
        "permit ipv6 any any",
        "permit ip any any",
        "permit udp any eq boot",
        "ipv6 access-list IPv6-Deny-All",
        "ip access-list extended AutoQos",
        "ip access-list extended VSL-",
        "ipv6 access-list VSL-",
        "stopbits",
        "track ",
        "permit ip any 224",
        "vrf",
        "threshold",
        "timeout",
        "frequency",
        "limit-resource",
        "feature",
        "hardware",
        "copp",
        "bfd",
        "rmon event",
        "rd auto",
        "route-target",
        "vpc domain",
        "host-reachability",
        "vpc peer-link",
        "nve1",
        "ip forward",
        "advertise virtual-rmac",
        "medium p2p",
        "ip router ospf",
        "port-type",
        "icam ",
        "boot ",
        "log-neighbor-changes",
        "update-source",
        "nv overlay",
        "tacacs-server",
        # Shell specific
        "access-list 1 ",
        "access-list 16 ",
        "access-list 22 ",
        "route-map STATIC-TO-OSPF",
        "permit ipv6 any FF02::/124",
        "module provision",
        "chassis-type",
        "mac address-table",
        "ntp source",
        "clock",
        "switch ",
        "vtp m",
        "mls qos",
        "subject-",
        "priority-queue",
        "version",
        "service",
        "platform",
        "interface",
        "switchport",
        "spanning",
        "aaa",
        "option",
        "flow",
        "crypto pki",
        "certificate",
        "negoti",
        "cdp",
        "encapsu",
        "bandwi",
        "ip pim",
        "no ",
        "auto-cost",
        "snmp-server enable traps",
        "banner",
        "line",
        "transport",
        "access-cl",
        "ipv6 access-class",
        "exec-timeout",
        "session-timeout",
        "call-home",
        "contact-email-addr",
        'profile "Cisco',
        "escape-",
        "mab",
        "dot1x",
        "authentication",
        "shutdown",
        "ip http",
        "ip ssh",
        "ip ftp",
        "ip tf",
        "iox",
        "ip tacacs",
        "snmp",
        "ip radi",
        "server-private",
        "client ",
        "udld",
        "table",
        "ip dhcp",
        "login",
        "enrollment",
        "revocation",
        "rsakeypair",
        "license",
        "errdisable",
        "memory",
        "match",
        "policy-map",
        "class",
        "queue-",
        "set ",
        "auto",
        "vlan",
        "ip ospf network",
        "ip mtu",
        "tunnel source",
        "channel-group",
        "ip helper-address ",
        "router ospf",
        "capability",
        "ip forward",
        "remark",
        "ip sla",
        "slot",
        "load-interval",
        "stackwise-virtual",
        "domain ",
        "ip vrf ",
        "default copy",
        "quit",
        "cabundle ",
        "diagnostic ",
        "transceiver",
        "monitoring",
        "ip access-list standard network_management",
        "control-plane",
        "active",
        "restconf",
        "destination transport-method",
        "area ",
        "radius server",
        "key 7 ",
        "standby 1 preempt",
        "ip flow",
        "downshift",
        "alarm ",
        "syslog ",
        "notifies ",
        "map ",
        "ptp ",
        "auth-type",
        "system mtu",
        "ip routing",
        "deadtime",
        "port",
        "random-detect ",
        "shape ",
        "exceed-",
        "conform-",
        "multilink",
        "subscriber",
        "config rogue",
        "config qos",
        "config license",
        "config logging syslog level",
        "config snmp v3user",
        "config media-stream",
        "config advanced",
        "config radius",
        "config mgmtuser",
        "config rf-profile",
        "config custom-web",
        "config flexconnect",
        "config acl rule source port",
        "config acl rule destination port",
        "config acl rule add",
        "config acl rule proto",
        "config acl rule dir",
        "config spann",
        "config wlan aaa-",
        "config wlan mfp",
        "config wlan broadcast",
        "config wlan create",
        "config wlan band-",
        "config wlan exclusionlist",
        "config wlan dms",
        "config wlan qos",
        "config wlan security",
        "config wlan interface",
        "config wlan media-stream",
        "config wlan session-",
        "config wlan nac",
        "config wlan mac-filtering",
        "config aaa",
        "config wps",
        "config rfid",
        "config 802.11",
        "config tacacs",
        "config trapflags",
        "config ap",
        "config mdns",
        "config location",
        "config interface vlan",
        # "config interface dhcp",
        "config interface create",
        "config database",
        "config network secureweb",
        "config network webmode",
        "config network ssh",
        "config network usertimeout",
        "config network arptimeout",
        "config network multicast",
        "config location",
        "config switchconfig",
        "config ipv6 disable",
        "config macfilter",
        "config lag enable",
        "config certificate generate",
        "config license",
        "config logging buffered",
        "config logging syslog level",
        "config nmsp",
        "config wlan radius_server",
        "config 802.11b",
        "transfer ",
        "config wlan wmm",
        "config wlan enable",
        "config wlan apgroup wlan-radio-policy",
        "config wlan apgroup hyperlocation",
        "config wlan apgroup qinq",
        "config wlan apgroup interface-mapping",
    ),
    "paloalto": (
        "set shared certificate",
        "set panorama certificate",
        "set deviceconfig system service",
        "set deviceconfig system update",
        "set deviceconfig system log-",
        "set deviceconfig system speed-",
        "set deviceconfig system timezone",
        "set deviceconfig system eth1 service",
        "set deviceconfig system eth1 speed-",
        "set deviceconfig system type",
        "set deviceconfig system snmp-setting",
        "set deviceconfig system device-telemetry",
        "set deviceconfig setting management",
        "set mgt-config users",
        "set mgt-config password",
        "set panorama log-settings traffic",
        "set network ike",
        "set network qos",
        "set network tunnel",
        "set shared",
        "set rulebase",
        "set zone",
        "set application",
        "set service",
        "set schedule"
    )
}

standard_keywords = {
    "paloalto": (
        "set",
        "protocol",
        "shared",
        "botnet",
        "configuration",
        "qos",
        "profile",
        "default",
        "ike",
        "gateway",
        "application",
        "service",
        "application-group",
        "service-group",
        "rulebase",
        "zone",
        "mgt-config",
        "users",
        "password-complexity",
        "default-security-rules",
        "crypto-profiles",
        "profiles",
        "interface",
        "ethernet",
        "deviceconfig",
        "system",
    ),
    "aruba": (
        "aaa",
        "authentication",
        "auth",
        "position",
        "jitter",
        "frequency",
        "vpnc",
        "data",
        "dot11g",
        "dot11a",
        "bcast",
        "hide",
        "eirp",
        "20mhz",
        "dot11h",
        "160mhz",
        "url",
        "php",
        "page",
        "pause",
        "redirect",
        "ipv4",
        "ipv6",
        "dpi",
        "conductor",
        "factory",
        "dst",
        "src",
        "ipsecmap10",
        "map",
        "source",
        "guestcppm",
        "30mb",
        "roleui",
        "10mbdownstreamper",
        "mbits",
        "chi",
        "minh",
        "ho",
    ),
    "cisco": (
        "ip",
        "config",
        "acl",
        "action",
        "address",
        "network",
        "id",
        "area",
        "access" "list",
        "eq",
        "udp",
        "tcp",
        "range",
        "host",
        "any",
        "remark",
        "permit",
        "gt",
        "lt",
        "fragments",
        "position",
        "standard",
        "setmedprimary",
        "crashinfo",
        "mls",
        "interval",
        "setcommunity",
        "ffff",
        "ffe",
        "buffersize",
        "table",
        "null",
        "software",
        "upgrade",
        "auto",
        "docker",
        "hosting",
        "pkg",
        "start",
        "extended",
        "log",
        "gigabitethernet",
        "overload",
        "hmac",
        "vti",
        "ikev",
        "cbc",
        "sha",
        "inside",
        "outside",
        "cssm",
        "sampler",
        "interval",
        "keys",
        "mgcp",
        "none",
        "force",
        "model",
        "prefer",
        "ftp",
        "ssh",
        "tftp",
        "http",
        "tacacs",
        "ntp",
        "destination",
        "tunnel",
        "source",
        "snmp",
        "bfd",
        "eigrp",
        "ospf",
        "router",
        "loopback",
        "wan",
        "routing",
        "for",
        "snmptrap",
        "bootpc",
        "bootps",
        "single",
        "acl",
        "deny",
        "permit",
        "and",
        "or",
        "not",
        "if",
        "logging",
        "route",
        "static",
        "port",
        "ports",
        "netbios",
        "the",
        "to",
        "gre",
        "tunnel",
        "interface",
        "vlan",
        "isakmp",
        "crypto",
        "keyring",
        "all",
        "protocol",
        "ldap",
        "citrix",
        "keepalives",
        "dscp",
        "shell",
        "trap",
        "domain",
        "traffic",
        "queue",
        "sequence",
        "ipv6",
        "loopbacks",
        "mgmnt",
        "icmp",
        "audio",
        "video",
        "catchall",
        "voice",
        "classify",
        "catch",
        "acct",
        "port",
        "auth",
        "ipv4",
        "vtp",
        "mode",
        "z1",
        "zc",
        "default",
        "gateway",
        "line",
        "vty",
        "nhs",
        "nbma",
        "shortcut",
        "user",
        "printer",
        "hold",
        "hostname:",
        "location:",
        "source",
        "icmp",
        "echo",
        "vrf",
        "office",
        "client",
        "md",
        "management",
        "cost",
        "6to4",
        "addresses",
        "site",
        "local",
        "multicast",
        "packets",
        "source",
        "route",
        "transport",
        "every",
        "subnet",
        "everything",
        "it",
        "else",
        "routing-type",
        "mobile-ipv6",
        "undetermined",
        "site",
        "preference",
        "less",
        "from",
        "loopback",
        "allow",
        "lan",
        "owner",
        "sdwan",
        "filter",
        "udp",
        "jitter",
        "default",
        "community",
        "denycommunity",
        "distance",
        "route",
        "reflector",
        "client",
        "setmedsecondary",
        "denycommunity",
        "both",
        "summary",
        "only",
        "aggregate",
        "ebgp",
        "multihop",
        "tag",
        "summary",
        "address",
        "suppress",
        "link",
        "nd",
        "ra",
        "suppress",
        "enable",
        "original",
        "input",
        "netflow",
        "ratio",
        "of",
        "record",
        "entries",
        "active",
        "cache",
        "timeout",
        "collector",
        "exporter",
        "unicast",
        "expiry",
        "time",
        "watch",
        "admission",
        "unreachable",
        "traceroute",
        "time",
        "exceeded",
        "echo",
        "ftp",
        "data",
        "established",
        "packet",
        "too",
        "big",
        "administratively",
        "prohibited",
        "esp",
        "www",
        "block",
        "routes",
        "an",
        "list",
        "netbios",
        "default",
        "originate",
        "activate",
        "next",
        "hop",
        "self",
        "path",
        "update",
        "timers",
        "peer",
        "group",
        "listen",
        "dhcp",
        "dns",
        "lookup",
        "key",
        "multipoint",
        "protection",
        "forced",
        "path",
        "redirect",
        "holdtime",
        "network",
        "authentication",
        "nhrp",
        "esp",
        "aes",
        "transform",
        "set",
        "idle",
        "seconds",
        "security",
        "association",
        "ipsec",
        "invalid",
        "spi",
        "recovery",
        "mtu",
        "fragmentation",
        "dial",
        "limit",
        "periodic",
        "local",
        "dpd",
        "identity",
        "lifetime",
        "profile",
        "pre",
        "shared",
        "key",
        "peer",
        "group",
        "integrity",
        "proposal",
        "encryption",
        "management",
        "network",
        "clock",
        "synchronization",
        "automatic",
        "exit",
        "seq",
        "le",
        "inboud",
        "outbound",
        "pim",
        "no",
        "with",
        "community",
        "new",
        "format",
        "null0",
        "mask",
        # 'neighbor',
        "access",
        "in",
        "out",
        "send",
        "soft",
        "reconfiguration",
        "prefix",
        "media",
        "type",
        "unicast",
        "verify",
        "reverse" "path",
        "decrement",
        "increment",
        "priority",
        "track",
        "standby",
        "policy",
        "route",
        "map",
        "policy",
        "keepalice",
        "adjust",
        "mss",
        "up",
        "down",
        "delay",
        "extended",
        "standard",
        "description",
        "ewlc",
        "control",
        "topology",
        "control",
        "forwarding",
        "lvx",
        "transit",
        "ewlc",
        "inter",
        "fed",
        "openflow",
        "exception",
        "egr",
        "exception",
        "nfl",
        "sampled",
        "rpf",
        "failed",
        "punt",
        "webauth",
        "lvx",
        "control",
        "forus",
        "resolution",
        "end",
        "station",
        "high",
        "rate",
        "applications",
        "mcast",
        "control",
        "dot",
        "gen",
        "broadcast",
        "stackwise",
        "virtual",
        "oob",
        "low",
        "latency",
        "snooping",
        "topology",
        "system",
        "critical",
        "gold",
        "pkt",
        "icmpgen",
        "broadcast",
        "l2lvxcntrl",
        "protosnoop",
        "puntwebauth",
        "mcastdata",
        "transit",
        "dot",
        "xauth",
        "swfwd",
        "lvxdata",
        "forustraffic",
        "forusarp",
        "mcastendstn",
        "openflow",
        "exception",
        "egrexcption",
        "nflsampled",
        "rpffailed",
        "twe",
        "eth",
        "channel",
        "systems",
        "channel",
        "ipv",
    ),
}


class ThemedConsole:
    def __init__(self, color_scheme="default"):
        self.set_color_scheme(color_scheme)

    def set_color_scheme(self, color_scheme):
        if color_scheme not in COLOR_SCHEMES:
            print(f"Warning: Unknown color scheme '{color_scheme}'. Using default.")
            color_scheme = "default"

        self.color_scheme = color_scheme
        self.colors = COLOR_SCHEMES[color_scheme]

        # Create a custom theme that maps all color names to our scheme
        theme_styles = {}
        for color in ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]:
            theme_styles[color] = Style(color=self.colors.get(color, color))

        # Add special styles
        theme_styles["bold"] = Style(bold=True)

        self.theme = Theme(theme_styles)
        self.console = Console(theme=self.theme)

    def print(self, *objects, sep=" ", end="\n", style=None, **kwargs):
        if style:
            style = self.colors.get(style, style)
        self.console.print(*objects, sep=sep, end=end, style=style, **kwargs)

    def __getattr__(self, name):
        return getattr(self.console, name)

    # def __setattr__(self, name, *args, **kwargs):
    #     return setattr(self.console, name, *args, **kwargs)


console = ThemedConsole()

# Define session object to handle all https requests
# Handle rate-limit and server errors
retries = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"],
    backoff_factor=2,
)

adapter = HTTPAdapter(max_retries=retries, pool_connections=10)
session = requests.Session()
session.mount("https://", adapter)
session.headers.update({"Content-Type": "application/json"})

# Precise match to IP, however search takes over 60 seconds
# ip_regexp = re.compile(r'(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)\.?\b){4}')
# Generic 4 1-3 numbers, lots of false positives but search takes 32 seconds
ip_regexp = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

subnet_regexp = re.compile(
    r"(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/((?:[1-2][0-9])|(?:3[0-2])|(?:[0-9]\b))"
)


def worker():
    """
    Thread waiting for data to get saved in a report file (whatever received as args,kwargs passed into append_df_to_excel)
    """
    while True:
        save_task = save_queue.get()
        with save_lock:
            append_df_to_excel(*save_task['args'], **save_task['kwargs'])
        save_queue.task_done()


def start_worker():
    """
    Start the file saving thread
    """
    global worker_thread
    if worker_thread is None or not worker_thread.is_alive():
        worker_thread = threading.Thread(target=worker, daemon=True)
        worker_thread.start()


def queue_save(*args, **kwargs):
    """
    Queing received data for saving thread to process
    """
    start_worker()
    save_task = {
        'args': args,
        'kwargs': kwargs
    }
    save_queue.put(save_task)


def wait_for_all_saves():
    """
    Waiting for all saving tasks to finish here
    """
    save_queue.join()


def yieldlines(thefile, whatlines):
    return ((i, x) for i, x in enumerate(thefile) if i in whatlines)


def measure_execution_time(func):
    def wrapper(*args, **kwargs):
        # args[0] should be logger
        # print(args[1])
        if args and len(args) > 1 and type(args[1]) is logging.Logger:
            logger = args[1]
        else:
            logger = None
        start_time = perf_counter()
        result = func(*args, **kwargs)
        end_time = perf_counter()
        execution_time = end_time - start_time
        if logger:
            logger.info(
                f"Function {func.__name__} took {execution_time:.4f} seconds to execute"
            )
        else:
            print(
                f"Function {func.__name__} took {execution_time:.4f} seconds to execute"
            )
        return result

    return wrapper


def interrupt_handler(logger: logging.Logger, signum: int, frame: any) -> None:
    """
    Signal handler for SIGINT (Ctrl+C) interruption.

    @param signum: Signal number.
    @param frame: Current stack frame.
    """
    if isinstance(logger, logging.Logger):
        logger.info(f"CTRL-C Interrupt({signum}) - Terminating... Stack:{frame}")

    exit_now(logger, exit_code=1, message="Interrupted... Exiting...")


def read_single_keypress():
    # Save the current terminal settings
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        # Switch terminal to raw mode to capture single key press without enter
        tty.setraw(sys.stdin.fileno())

        # Read a single character
        ch = sys.stdin.read(1)
    finally:
        # Restore the terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return ch


def read_config(cfg: dict, config_file: str = ".cn") -> dict:
    """
    Reads configuration file

    @param config_file: path to configuration file with filename(can be
        relative or absolute)

    @return cfg(dict): populated dictionary with configuration values
        read from the file or default values(if config missing specific
        parameter)
    """

    if os.path.exists(config_file):
        config = configparser.ConfigParser()
        config.read(config_file)

        read_cfg = {
            "api_endpoint": config.get("api", "endpoint", fallback=cfg["api_endpoint"]),
            "logfile_location": os.path.expanduser(
                config.get("logging", "logfile", fallback=cfg["logfile_location"])
            ),
            "log_level_str": config.get("logging", "level", fallback="INFO"),
            "report_filename": os.path.expanduser(
                config.get("output", "filename", fallback=cfg["report_filename"])
            ),
            "gpg_credentials": os.path.expanduser(
                config.get("gpg", "credentials", fallback=cfg["gpg_credentials"])
            ),
            "auto_save": config.getboolean("output", "auto_save", fallback=True),
            "store": os.path.expanduser(
                config.get(
                    "config_repository", "storage_directory", fallback=cfg["store"]
                )
            ),
            "regions": config.get(
                "config_repository", "regions", fallback="ap,eu,am"
            ).split(","),
            "vendors": config.get(
                "config_repository",
                "vendors",
                fallback="cisco,aruba,f5,bluecoat,paloalto",
            ).split(","),
            "cache_directory": os.path.expanduser(
                config.get("cache", "directory", fallback=cfg["cache_directory"])
            ),
            "cache": config.get("cache", "enabled", fallback=cfg["cache"]),
            "theme": config.get("theme", "theme", fallback=cfg["theme"]),
        }
    else:
        read_cfg = cfg

    return read_cfg


def data_to_dict(column_names: list, data: list) -> dict:
    """
    Converts a list of column names and corresponding data into a dictionary.

    @param column_names: List of column names.
    @param data: List of lists representing the data rows.
    @return: Dictionary with column names as keys and data as values.
    """
    # Function need two dimension array, in case if only single raw was sent it might be a simple list only

    result_dict = {}

    if isinstance(data, list) and len(data) > 0:
        if not isinstance(data[0], list):
            data = [data]
    else:
        # if nothing to save or data is not list - return empty dict
        return result_dict

    # Iterate through column names
    for col_name in column_names:
        result_dict[col_name] = []

    # Iterate through data rows
    for row in data:
        # Iterate through column names and corresponding row data
        for col_name, col_data in zip(column_names, row):
            # Append data to the corresponding key in the dictionary
            result_dict[col_name].append(col_data)

    return result_dict


def print_search_config_data(data: list, color_scheme: str = "default") -> None:
    """
    Prints the configuration search data in a formatted manner.
    Sort the data array based on the device name and line number, then prints out data per device.
    Columns in the data are as follows:
    [ip(search ip matching), device_name(str), line_num(int), config_line(str)]

    @param data(list[list]): config data to print out
    """

    if len(data) == 0:
        # Nothing to print
        return

    if color_scheme not in COLOR_SCHEMES:
        # print(f"Warning: Unknown color scheme '{color_scheme}'. Using default.")
        color_scheme = "default"

    colors = COLOR_SCHEMES[color_scheme]

    data.sort(key=lambda x: (x[1], x[2]))

    current_device = ""
    current_line = 0

    for row in data:
        device = row[1].upper()
        line_number = int(row[2])
        line = row[3]

        if device != current_device:
            current_device = device
            current_line = line_number
            console.print(f"\n[{colors['title']}]Device {current_device}[/]:", highlight=False)
            console.print(f"[{colors['header']}]Line {current_line}:[/]", highlight=False)
        elif line_number - current_line >= 100:
            current_line = line_number

            console.print(f"\n[{colors['header']}]Line {current_line}:[/]", highlight=False)

        console.print(f"[{colors['value']}]{line}[/]", highlight=False)
    console.print("\n")

    return


# @measure_execution_time
def make_dir_list(logger: logging.Logger, cfg: dict) -> list:
    """
    Reads cfg and makes up a list of directories to read devices from

    @param logger(Logger): logger instance.

    @return list
    """
    dir_list = []
    for vendor in cfg["vendors"]:
        vendor = vendor.strip()
        dir_path = os.path.join(cfg["store"], vendor)
        if not check_dir_accessibility(dir_path, logger):
            logger.info(
                f"Configuration Repository - No data directory for {vendor.upper()} found!"
            )
            continue

        for device_type in os.listdir(dir_path):
            for region in cfg["regions"]:
                region = region.strip()
                device_directory = os.path.join(dir_path, device_type, region)
                if not check_dir_accessibility(device_directory, logger):
                    logger.info(
                        f"Configuration Repository - No data directory for {region.upper()} found!"
                    )
                    continue
                dir_list.append(device_directory)

    return dir_list


def search_config(
    logger: logging.Logger,
    cfg: dict,
    folder: str,
    nets: list[ipaddress.IPv4Network],
    search_terms: list[re.Pattern],
    search_input: str,
) -> tuple[list, set]:
    """
    Searches files in a given directory for keywords(regex) or subnet addresses, or a single IP
    @param logger: logger instance
    @param cfg: configuration parameters
    @param folder: directory path
    @param nets: list of ipaddress.IPv4Network objects
    @param search_terms: list of regular expressions to match
    @param search_input: only used in interacive mode when user explicitly looks for a single subnet/keyword

    @return None
    """
    colors = get_global_color_scheme(cfg)

    data_to_save = []
    matched_nets = set()
    dir_list = os.listdir(folder)
    parts = folder.split("/")
    vendor = str(parts[4]).capitalize()
    device_type = str(parts[5]).upper()
    region = str(parts[6]).upper()
    with console.status(  
        f"[{colors['description']}]Searching through [{colors['type']}]{vendor.upper()}/{device_type}[/] configurations in [{colors['hostname']}]{region}[/] region...[/]",
        spinner="dots12",
    ):

        with ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(
                    matched_lines,
                    logger,
                    os.path.join(folder, device),
                    vendor,
                    nets,
                    search_terms,
                    search_input,
                )
                for device in dir_list
            }
            results = [future.result() for future in futures]
        for result in results:
            # result has a tuple with two lists:
            # list 1 - actual config matches
            # list 2 - matched subnets
            if result and len(result[0]) > 0:
                data_to_save.extend(result[0])
            if result and len(result[1]) > 0:
                matched_nets.update(result[1])

    return (data_to_save, matched_nets)


def search_config_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Searches configuration repository files for keywords(regex) or subnet addresses, or a single IP

    Requests user to provide a search string or subnet with mask (IP/XX form)
    Validates user input, expands subnet to include all IPs within the subnet
    Performs search over configuration repository for keywords or expanded IP list
    Displays formatted data to a user (calls print_search_config_data)
    Saves references to tabs/config lines in 'Config Check' tab
    Copies device configurations into new tabs = device names

    @param logger(Logger): logger instance.

    @return None
    """
    colors = get_global_color_scheme(cfg)

    logger.info("Configuration Repository - Search Request")

    console.print(
        f"[{colors['description']}]Enter subnet([{colors['code']}]IP_ADDRESS/[MASK][/]) or keyword(regular expression), one item per line[/]\n"
        f"[{colors['description']}]Empty input line starts the process[/]\n"
        "\n"
        f"[{colors['header']}]Subnet Examples:[/]\n"
        f"[{colors['success']} {colors['bold']}]10.10.10.0/24[/]\n"
        f"[{colors['success']} {colors['bold']}]134.143.169.176/29[/]\n"
        f"[{colors['header']}]Keywords Regex Examples:[/]\n"
        f"[{colors['success']} {colors['bold']}]router bgp 655\\d+$[/]\n"
        f"[{colors['success']} {colors['bold']}]neighbor \\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}} description VOCUS\\s+[/]\n"
    )

    search_input = "none"
    keyword_regexps = []
    networks = None
    validated_search_input = []
    while True:
        search_input = read_user_input(logger, "").strip()
        if search_input == "":
            break

        # Check if input looks like an IP address or subnet
        if "/" not in search_input and re.match(ip_regexp, search_input):
            # IP address without mask, append default mask of /32
            search_input += "/32"
            validated_search_input.append(search_input)

        if "/" in search_input and re.match(ip_regexp, search_input):
            # IP address with mask
            try:
                network = ipaddress.ip_network(search_input, strict=False)
            except ValueError:
                logger.info(
                    f"User input - Not matching network address: {search_input}"
                )
                console.print(
                    f"[{colors['error']}]Invalid subnet format.\n[/]"
                    f"[{colors['info']}]Enter a valid subnet or IP (e.g., 192.168.1.0/24 or 192.168.1.10)[/]"
                )
                continue
            else:
                if (
                    network.is_multicast
                    or network.is_unspecified
                    or network.is_reserved
                    or network.is_link_local
                ):
                    logger.info(f"User input - Invalid subnet: {search_input}")
                    console.print(
                        f"[{colors['error']}]Invalid IP - multicast, broadcast and reserved subnets excluded.[/]\n"
                        f"[{colors['info']}]Enter a valid non-reserved subnet or IP (e.g., 10.10.1.0/24 or 192.168.1.10)[/]"
                    )
                    continue
                if networks is None:
                    networks = []
                networks.append(network)
                validated_search_input.append(search_input)
                continue

        if len(search_input) < MIN_INPUT_LEN and not is_valid_site(search_input):
            logger.info(f"User input - Input keyword is too short: {search_input}")
            console.print(f"[{colors['error']}]Input keyword is too short: {search_input}[/]")
            # Skipping wrong line
            continue

        # Try to compile the input as a regular expression
        try:
            re.compile(search_input, re.IGNORECASE)
        except re.error as e:
            logger.info(f"User input - Invalid regexp: {e}")
            console.print(f"[{colors['error']}]Invalid regular expression - {e.msg}[/]")
            # Skipping wrong line
            continue
        else:
            # Last added regexp or string line is considered as search term.
            # However, if subnets were supplied, we ignore it
            # keyword_regexps.append(keyword_regexp)
            keyword_regexps.append(search_input)
            validated_search_input.append(search_input)
            continue

    if not networks and len(keyword_regexps) == 0:
        return

    log_value = ", ".join(validated_search_input)
    logger.info(f"User input - {log_value}")

    data_to_save = []
    matched_nets = set()

    start = perf_counter()

    if cfg["cache"] and cfg["dc"].get("updated", 0) > 0:
        with console.status(f"[{colors['description']}]Searching through configurations...[/]", spinner="dots12"):
            data_to_save, matched_nets = search_cache_config(
                logger, cfg, "", networks, keyword_regexps, "\n".join(validated_search_input)
            )
    else:
        for folder in make_dir_list(logger, cfg):
            lines, nets = search_config(
                logger, cfg, folder, networks, keyword_regexps, "\n".join(validated_search_input)
            )
            data_to_save.extend(lines)
            matched_nets.update(nets)

    end = perf_counter()
    logger.info(
        f"Configuration Repository - Search took {round(end-start, 3)} seconds!"
    )
    console.print(
        f"[{colors['description']}]Configuration Repository - Search took [{colors['success']}]{round(end-start, 3)}[/] seconds![/]"
    )

    if len(data_to_save) == 0:
        logger.info("Configuration Repository - No matches found!")
        console.print(f"[{colors['error']}]No matches found![/]")
        return

    if networks:
        missing_nets = list(set(networks) - set(matched_nets))
        for missed_net in missing_nets:
            if str(missed_net).endswith("/32"):
                missed_net = str(missed_net)[:-3]
            console.print(
                f"[{colors['description']}]Subnet [{colors['hostname']}]{missed_net}[/] - [{colors['error']}]No matches found[/]"
            )
    else:
        missing_nets = None

    # data = [
    #     [search_input, device, line_num, line_content] for search_input, device, line_num, line_content, _ in data_to_save
    # ]
    # sorted_data = sorted(data, key=itemgetter(1, 2))
    sorted_data = remove_duplicate_rows_sorted_by_col(data_to_save, 2)
    print_search_config_data(sorted_data, cfg["theme"])

    # Saving data automatically unless user requested not to (relies on global auto_save flag)
    if cfg["auto_save"]:
        save_found_data(
            logger, cfg, sorted_data, missing_nets, matched_nets, "Config Check"
        )


def demob_site_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide FQDN string
    Validates user input
    Calls do_fancy_request
    Calls process_site_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """
    colors = get_global_color_scheme(cfg)

    console.print(
        "\n"
        f"[{colors['warning']} {colors['bold']}]This request is to verify if any subnets exist on the devices for a given sitecode, subnets pulled from Infoblox matching description field[/]\n"
        f"[{colors['error']} {colors['bold']}]Always check provided results[/]\n"
        f"[{colors['description']}]Request has a limit of [{colors['error']} {colors['bold']}]50[/] subnet records per site[/]\n"
        f"[{colors['description']}]Type in location site code to perform search[/]\n"
        f"[{colors['description']}]Supported site code format: [{colors['success']} {colors['bold']}]XXX, XXXXXXX, XXX-XX\\[XX][/]\n"
        f"[{colors['header']}]Site Code Examples:[/]\n"
        f"[{colors['success']} {colors['bold']}]AMS-DC, WND-RYD[/]\n"
    )

    raw_input = read_user_input(logger, "Enter location site code: ").strip()

    logger.info(f"User input - {raw_input}")
    if is_valid_site(raw_input):
        sitecode = raw_input.upper()
        logger.info(f"User input - Sitecode search for {sitecode}")
    else:
        logger.info(f"User input - Incorrect site code {raw_input}")
        console.print(f"[{colors['error']}]Incorrect site code[/]")
        return

    uri = f"network?comment:~={sitecode}&_max_results=50"
    processed_data = {}

    data = do_fancy_request(
        logger,
        cfg,
        message=f"[{colors['description']}]Fetching data for [{colors['header']}]{sitecode}[/]...[/]",
        endpoint=cfg["api_endpoint"],
        uri=uri,
    )

    if data and len(data) > 0:
        # process_data if not empty has 'location' key with subnet data
        processed_data = process_data(logger, type=f"location_{sitecode}", content=data)

    if len(processed_data.get("location", "")) == 0:
        logger.info("Request Type - Location Information - No information received")
        console.print(f"[{colors['error']}]No [{colors['success']} {colors['bold']}]{sitecode.upper()}[/] subnets registered in Infoblox[/]")
    else:

        print_table_data(logger, cfg, processed_data)

        console.print(
            f'[{colors["description"]}]Received {len(processed_data["location"])} subnet records registered for [{colors["success"]} {colors["bold"]}]{sitecode}[/]'
        )
        logger.info(f"Request Type - Location Information - Received {len(processed_data['location'])} subnet records")
        logger.debug(
            f"Request Type - Location Information - Processed data {processed_data}"
        )

    if read_user_input(logger, f"[{colors['warning']}]Would you like to proceed searching configuration files(Y/N)? [/]").lower() != "y":
        return

    # Now for each location subnet we have to perform configuration lookup, it might take longer than we expect
    locations = processed_data["location"]
    networks = []
    skipped_networks = []
    country = None
    for location in locations:
        net = ipaddress.ip_network(location["network"])
        if country is None:
            country = location["comment"][:2].upper()
        if net.is_multicast or net.is_unspecified:
            skipped_networks.append(location["network"])
        else:
            networks.append(net)

    start = perf_counter()
    data_to_save = []
    search_terms = []
    matched_nets = set()

    if len(skipped_networks) > 0:
        console.print(
            f"[{colors['warning']} {colors['bold']}]Site {sitecode} has reserved/mulicast networks registered in Infoblox[/]\n"
        )
        for skipped_net in skipped_networks:
            console.print(
                f"[{colors['info']} {colors['bold']}]Skipping reserved/mulicast network: [{colors['header']} {colors['bold']}]{skipped_net}[/]"
            )
        console.print("\n")

    # Creating single search term to match WLC configs (Shell specific)
    if country:
        pattern = rf'\b(?:{country}{re.escape(sitecode.replace("-", ""))}|{re.escape(sitecode)}[_0-9]+[-\w\d]*)\b'
    else:
        pattern = rf'\b(?:[A-Z]{{2}}{re.escape(sitecode.replace("-", ""))}|{re.escape(sitecode)}[_0-9]+[-\w\d]*)\b'

    # compiled_pattern = re.compile(pattern)
    search_terms.append(pattern)

    if cfg["cache"] and cfg["dc"].get("updated", 0) > 0:
        with console.status(f"[{colors['description']}]Searching through configurations...[/]", spinner="dots12"):
            data_to_save, matched_nets = search_cache_config(
                logger, cfg, "", networks, search_terms, search_input=sitecode
            )
    else:
        for folder in make_dir_list(logger, cfg):
            lines, nets = search_config(
                logger, cfg, folder, networks, search_terms, search_input=sitecode
            )
            data_to_save.extend(lines)
            matched_nets.update(nets)

    end = perf_counter()
    console.print(
         f"[{colors['description']}]Configuration Repository - Search took [{colors['success']}]{round(end-start, 3)}[/] seconds![/]"
    )
    logger.info(
        f"Configuration Repository - Search took {round(end-start, 3)} seconds!"
    )

    if len(data_to_save) == 0:
        logger.info(f"Configuration Repository - No matches for {sitecode} found!")
        console.print(f"[{colors['error']}]No matches found![/]")
        return

    missing_nets = list(set(networks) - set(matched_nets))
    if len(missing_nets) > 0:
        for missed_net in missing_nets:
            if str(missed_net).endswith("/32"):
                missed_net = str(missed_net)[:-3]
            console.print(
                f"[{colors['description']}]Subnet [{colors['success']} {colors['bold']}]{missed_net}[/] - [{colors['error']}]No matches found[/]"
            )
    else:
        missing_nets = None

    # data = [
    #     [search_input, device, line_num, line_content] for search_input, device, line_num, line_content in data_to_save
    # ]
    # sorted_data = sorted(data, key=itemgetter(1, 2))
    sorted_data = remove_duplicate_rows_sorted_by_col(data_to_save, 2)
    print_search_config_data(sorted_data, cfg["theme"])

    # Saving data automatically unless user requested not to (relies on global auto_save flag)
    if cfg["auto_save"]:
        save_found_data(
            logger, cfg, data_to_save, missing_nets, matched_nets, "Demob Site Check"
        )


def save_found_data(
    logger: logging.Logger,
    cfg: dict,
    data: list,
    missed_nets: set,
    matched_nets: set,
    sheet: str = "Config Check",
) -> None:
    """
    Saves provided data in report file, used by search_config_request and demob_site_request functions

    @param logger(Logger): logger instance
    @param cfg(dict): configuration params
    @param data(list): data to save
    @param sheet(str): excel tab to save config matches

    @return: None
    """

    logger.info(f"Configuration Search - {sheet} saving configuration matches")

    # Adding search results information about subnets
    search_input = str(data[0][0])
    if missed_nets or matched_nets:
        missed_nets_data = [
            [search_input, str(net), "No match"] for net in missed_nets if net
        ]
        matched_nets_data = [
            [search_input, str(net), "Used"] for net in matched_nets if net
        ]
        save_nets_data = []
        save_nets_data.extend(missed_nets_data)
        save_nets_data.extend(matched_nets_data)
        if is_valid_site(search_input):
            columns = ["Site Code", "Subnet", "Status"]
        else:
            columns = ["Search Terms", "Subnet", "Status"]
        # Saving Missed Subnet Data first
        if save_nets_data:
            # append_df_to_excel(
            queue_save(
                logger,
                cfg["report_filename"],
                columns,
                save_nets_data,
                sheet_name=sheet,
                index=False,
                force_header=True,
            )
    # Adding hyperlinks to Line number
    columns = ["Search Terms", "Device", "Line number", "Line"]
    sorted_data = [
        [
            search_input,
            device,
            "=HYPERLINK(\"#'{}'!A{}\", {})".format(device, int(index) + 1, index),
            line,
            _,
        ]
        for search_input, device, index, line, _ in data
    ]
    # Saving Check data
    # append_df_to_excel(
    queue_save(
        logger,
        cfg["report_filename"],
        columns,
        sorted_data,
        sheet_name=sheet,
        index=False,
        force_header=True,
    )

    # Adding device configurations to the report
    # If cache exists get full filename from cache, else rely on additional column provided in sorted_data
    if cfg["cache"] and cfg["dc"].get("updated", False):
        device_list = {
            (device_name, cfg["dev_idx"][device_name.lower()].get("fname"))
            for _, device_name, _, _, _ in data
        }
    else:
        device_list = {(device_name, fname) for _, device_name, _, _, fname in data}
    # Not saving configs if we have more than 50 devices matched
    if len(device_list) > 50:
        logger.info(
            f"Too many devices({len(device_list)}) have matches, skipping report update"
        )
        return
    logger.info(f"Configuration Search - {sheet} saving device configs")

    for device, fname in device_list:
        # logger.debug(f'DEBUG Saving {device}, path {fname}')
        if fname is None:
            logger.error(
                f"{device} is missing full pathname information.. unable to save"
            )
            continue
        with open(fname, "r", encoding="utf-8") as f:
            file_content = f.readlines()
            queue_save(
                logger,
                cfg["report_filename"],
                columns=None,
                raw_data=file_content,
                sheet_name=device.upper(),
                index=False,
                skip_if_exists=True,
            )


# @measure_execution_time
def matched_lines(
    logger: logging.Logger,
    filename: str,
    vendor: str,
    ip_nets: list[ipaddress.IPv4Network],
    search_terms: list[re.Pattern],
    search_input: str,
) -> tuple[list, set]:
    """
    Looks up for matches in a file for a given list of IP networks or search patterns
    Returns data list

    @param logger(Logger): logger instance
    @param filename(str): filename to match data on
    @param vendor(str): vendor to filter lines with stopwords
    @param ip_nets(IPv4Network): subnets to lookup
    @param search_terms(list re.Pattern): list of keyword regexps to match
    @search_input(str): to save in file as info if provided

    @return: tuple[list, list] first list in tuple is the matched lines data, second list in tuple is the list of matched subnets
    """
    data_to_save = []
    search_term = None
    matched_nets = set()

    if ip_nets is None and search_terms is None:
        return (data_to_save, matched_nets)

    if os.path.isfile(filename):
        with open(filename, "r", encoding="utf-8") as f:
            file_content = f.readlines()

            # Strip spaces
            current_config = [line.strip() for line in file_content]

            device = f'{os.path.split(filename)[1].split(".")[0].upper()}'
            rows_to_save = {}

            # console.print(device)

            for index, current_line in enumerate(current_config):
                # if line starts with one of the frequent config commands with no key data - skip it
                if current_line.strip().startswith(
                    stop_words.get(vendor.lower(), ("NEVERMATCHED"))
                ):
                    continue
                # if there is a match in line check if we have ip_data and verify found IP within the subnet range
                if ip_nets:
                    found_matches = re.finditer(ip_regexp, current_line)

                    for match in found_matches:
                        try:
                            found_ip = ipaddress.ip_address(match.group())
                        except (re.error, ValueError):
                            logger.debug(
                                f"Config Check - Found {match.group()} bad IP(skipped) in {device.upper()} line {index}"
                            )
                            pass
                        else:
                            matched_subnet = next(
                                (net for net in ip_nets if found_ip in net), None
                            )
                            if matched_subnet:
                                matched_nets.add(matched_subnet)
                                logger.debug(
                                    f"Config Check - Found {found_ip} matching subnet {matched_subnet} in {device.upper()} line {index}"
                                )
                                rows_to_save[index] = f"{current_config[index]}"
                if search_terms:
                    for search_term in search_terms:
                        # logger.debug(f'DEBUG - Searching for {str(search_term)} in {current_line}')
                        matched = re.search(search_term, current_line, re.IGNORECASE)
                        if matched:
                            logger.debug(
                                f'Config Check - Found expressison "{matched}" in {device.upper()} line {index}'
                            )
                            rows_to_save[index] = f"{current_config[index]}"

        # Saving all gathered data to data_to_save array
        if len(rows_to_save) > 0:
            # Sorting by config line prior saving
            rows = [
                [search_input, device, index, line, filename]
                for index, line in sorted(
                    rows_to_save.items(),
                    key=lambda x: (x[0] if isinstance(x[0], int) else float("inf")),
                )
            ]

            data_to_save.extend(rows)

    return (data_to_save, matched_nets)


def append_df_to_excel(
    logger: logging.Logger,
    filename: str,
    columns: list,
    raw_data: list,
    sheet_name: str = "Sheet1",
    startrow: int = 0,
    truncate_sheet: bool = False,
    skip_if_exists: bool = False,
    force_header: bool = False,
    **to_excel_kwargs: any,
) -> None:
    """
    Append a DataFrame [df] to existing Excel file [filename] into [sheet_name] Sheet.
    If [filename] doesn't exist, then this function will create it.

    @param logger(Logger): logger instance.
    @param filename: File path or existing ExcelWriter
                     (Example: '/path/to/file.xlsx')
    @param columns(list): list of column names - headers
    @param raw_data: 2d array with data

    @param sheet_name: Name of sheet which will contain DataFrame.
                       (default: 'Sheet1')
    @param startrow: upper left cell row to dump data frame.
                     Per default (startrow=None) calculate the last row
                     in the existing DF and write to the next row...
    @param truncate_sheet: truncate (remove and recreate) [sheet_name]
                           before writing DataFrame to Excel file
    @param skip_if_exists: if sheet exists, do nothing
    @param force_header: write header no matter what
    @param to_excel_kwargs: arguments which will be passed to `DataFrame.to_excel()`
                            [can be a dictionary]

    @return: None

    Original Author: (c) [MaxU](https://stackoverflow.com/users/5741205/maxu?tab=profile)

    evgeny: - fixed append feature which was not working due to newer pandas version
            - added prepare_df helper function(creates df set)
            - added required parameters to integrate into common codebase
            - minor fixes/checks
    """

    def prepare_df(columns: list, data: list) -> pd.DataFrame:
        """
        Helper function prepares Pandas DataFrame
        """
        data_to_save = data_to_dict(columns, data)
        data_frame = pd.DataFrame.from_dict(data_to_save)

        return data_frame

    #  If columns were provided need to prepare data set, otherwise we have to save data as is
    if columns:
        df = prepare_df(columns, raw_data)
    else:
        df = pd.DataFrame(raw_data)

    # Excel file doesn't exist - saving and exiting
    if not check_file_accessibility(filename, logger):
        # Log report creation
        logger.info(f"Export - Report {filename} doesn't exist - creating...")
        df.to_excel(
            filename,
            sheet_name=sheet_name,
            startrow=startrow if startrow is not None else 0,
            **to_excel_kwargs,
        )

        # Log success
        logger.info(f"Export - {filename} - created successfully")

        return

    # ignore [engine] parameter if it was passed
    if "engine" in to_excel_kwargs:
        to_excel_kwargs.pop("engine", None)

    # To find out if there is any data in existing file and if it is there how many rows occupied
    try:
        existing_data = pd.read_excel(
            filename, sheet_name=sheet_name, engine="openpyxl"
        )
    # If no sheet in the workbook we get ValueError exception
    except ValueError:
        existing_data = ""

    filled_rows = len(existing_data)

    if filled_rows > 0 and skip_if_exists:
        return

    if filled_rows > 0 and not truncate_sheet:
        logger.info(
            f"Export - Found {filename} report - Sheet {sheet_name} has {filled_rows} rows"
        )
        # New data will be placed right after last row
        startrow = filled_rows + 1
    elif filled_rows > 0:
        logger.info(
            f"Export - Found {filename} report - Truncating {sheet_name}, adding new data"
        )
        startrow = 0
    else:
        logger.info(
            f"Export - Found {filename} report - No {sheet_name} sheet found, creating..."
        )
        startrow = 0

    with pd.ExcelWriter(
        filename, engine="openpyxl", if_sheet_exists="overlay", mode="a"
    ) as writer:

        # if force_header is set we always write header, otherwise
        # if filled_rows = 0 then we need header, otherwise header is already in the sheet
        # in no columns provided we dont need a header
        if columns and force_header:
            header = True
        elif columns:
            header = not bool(filled_rows)
        else:
            header = False

        # write out the data to the sheet
        df.to_excel(
            writer,
            startrow=startrow,
            header=header,
            sheet_name=sheet_name,
            **to_excel_kwargs,
        )

        # log success
        logger.info(f"Export - Updated {filename} successfully")

    return


def configure_logging(logfile_location: str, log_level=logging.INFO) -> logging.Logger:
    """
    Sets up logger facility

    @param logfile_location(str): path and filename to write log to
    @param log_level(int): severity level number for log message (logger.[INFO|WARNING|ERROR] and etc)

    @return instance(logger): initialised logger instance.
    """

    # Create a logger
    logger = logging.getLogger(__name__)

    # Set the log level
    logger.setLevel(log_level)

    # Create a file handler
    file_handler = ThreadSafeFileHandler(logfile_location)
    logger.addHandler(file_handler)

    # Create a formatter
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Add the formatter to the file handler
    file_handler.setFormatter(file_formatter)

    # Add the file handler to the logger
    logger.addHandler(file_handler)

    return logger


def validate_ip(ip: str) -> bool:
    """
    Validates an IP address using a regular expression.

    @param ip: IP address to validate

    @return: bool: True if the IP address is valid, False otherwise.
    """

    # Valid IP regex
    # ip_regex = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

    # pass the regular expression
    # and the string in search() method
    if re.search(ip_regexp, ip):
        return True

    return False


def is_valid_site(sitecode: str) -> bool:
    """
    Validates a site code using a regular expression.

    @param sitecode: Site code to validate.
    @return: True if the site code is valid, False otherwise.
    """

    # This regex allows for either three alphanumeric characters followed by a hyphen and another three alphanumeric characters,
    # or simply three alphanumeric characters without the hyphen.
    valid_site_regex = "^[a-z0-9]{7}$|^[a-z0-9]{3}$|^[a-z0-9]{3}(?:-[a-z0-9]{2,4})?$"

    if re.search(valid_site_regex, sitecode, re.IGNORECASE):
        return True

    return False


def is_fqdn(hostname: str) -> bool:
    """
    Validates a fully qualified domain name (FQDN) based on its structure and length.

    @param hostname: Hostname to validate.
    @return: True if the hostname is a valid FQDN, False otherwise.
    """
    if not 1 < len(hostname) < 253:
        return False

    # Remove trailing dot
    if hostname[-1] == ".":
        hostname = hostname[0:-1]

    #  Split hostname into list of DNS labels
    labels = hostname.split(".")

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = re.compile(r"^[a-z][a-z0-9][-a-z0-9]{0,61}[a-z0-9]?$", re.IGNORECASE)

    # Check that all labels match that pattern.
    return all(fqdn.match(label) for label in labels)


def parse_show_version(output: str) -> dict:
    # This function parses 'show version' output

    result = {
        "Software Version": "",
        "Software Image": "",
        "Part Number": "",
        "Uptime": "",
        "Serial Number": "",
        "Switches": []
    }

    # Extract Software Version
    version_match = re.search(r'(Version|Cisco IOS XE Software, Version)\s+([\d.()]+[A-Z]?\d*)', output)
    if version_match:
        result["Software Version"] = version_match.group(2)

    # Extract Software Image
    image_match = re.search(r'System image file is\s+"(.+)"', output)
    if image_match:
        result["Software Image"] = image_match.group(1)

    # Extract Uptime
    uptime_match = re.search(r'(\S+)?\s*uptime is (.+?)(?=\n)', output)
    if uptime_match:
        result["Uptime"] = f"{uptime_match.group(2)}"

    # Extract Serial Number
    serial_match = re.search(r'(Processor board ID|System Serial Number\s+:)\s*(\S+)', output)
    if serial_match:
        result["Serial Number"] = serial_match.group(2)

    return result


def parse_show_license_reservation(output: str) -> dict:
    # This function parses 'show license reservation' output

    result = {}

    # Extract License Reservation status
    license_reservation_match = re.search(r'License reservation: (\S+)', output)
    license_reservation = license_reservation_match.group(1) if license_reservation_match else 'UNKNOWN'

    sections = output.split('Specified license reservations:')
    overall_status = sections[0].strip()
    license_info = sections[1].strip() if len(sections) > 1 else ''

    # Parse overall status
    for block in re.split(r'\n\s+(?=(?:Active|Standby|Member))', overall_status):
        match = re.match(r'\s*(Active|Standby|Member): PID:([^,]+),SN:(\S+)', block)
        if match:
            device_type, pid, sn = match.groups()
            device_info = {
                'TYPE': device_type,
                'PID': pid,
                'SN': sn,
                'LICENSE_RESERVATION': license_reservation,
                'LICENSES': []
            }
            for line in block.split('\n')[1:]:
                if 'Status:' in line or 'Reservation status:' in line:
                    status_match = re.search(r'(?:Reservation )?[Ss]tatus: (.+?)(?: on (.+))?$', line)
                    if status_match:
                        device_info['RESERVATION_STATUS'] = status_match.group(1)
                        device_info['RESERVATION_DATE'] = status_match.group(2) if status_match.group(2) else ''
                elif 'Export-Controlled Functionality:' in line:
                    device_info['EXPORT_CONTROLLED'] = line.split(':')[1].strip()
                elif 'Last Confirmation code:' in line:
                    device_info['CONFIRMATION_CODE'] = line.split(':')[1].strip()
            result[sn] = device_info

    # Parse license info
    license_blocks = re.split(r'\n\s+(?=\S+\s+\()', license_info)
    for block in license_blocks:
        license_match = re.search(r'(\S+.*?) \((.*?)\):\s+Description: (.+?)\s+Total reserved count: (\d+)', block, re.DOTALL)
        if license_match:
            license_name, license_full_name, description, total_reserved = license_match.groups()
            enforcement_type = re.search(r'Enforcement type: (.+)', block)
            enforcement_type = enforcement_type.group(1) if enforcement_type else ''

            for device_block in re.findall(r'((?:Active|Standby|Member): PID:[^,]+,SN:\S+\s+(?:Authorization type:[^\n]+\s+)?License type:[^\n]+(?:\s+Start Date:[^\n]+\s+End Date:[^\n]+)?\s+Term Count: \d+)', block):
                device_match = re.search(r'(?:Active|Standby|Member): PID:[^,]+,SN:(\S+)', device_block)
                if device_match:
                    sn = device_match.group(1)
                    if sn in result:
                        license_info = {
                            'LICENSE_NAME': license_name,
                            'LICENSE_FULL_NAME': license_full_name,
                            'LICENSE_DESCRIPTION': description,
                            'TOTAL_RESERVED': total_reserved,
                            'ENFORCEMENT_TYPE': enforcement_type
                        }
                        auth_type = re.search(r'Authorization type: (.+)', device_block)
                        license_info['AUTHORIZATION_TYPE'] = auth_type.group(1) if auth_type else ''

                        license_type = re.search(r'License type: (\S+)', device_block)
                        license_info['LICENSE_TYPE'] = license_type.group(1) if license_type else ''

                        start_date = re.search(r'Start Date: (.+)', device_block)
                        license_info['START_DATE'] = start_date.group(1) if start_date else ''

                        end_date = re.search(r'End Date: (.+)', device_block)
                        license_info['END_DATE'] = end_date.group(1) if end_date else ''

                        term_count = re.search(r'Term Count: (\d+)', device_block)
                        license_info['TERM_COUNT'] = term_count.group(1) if term_count else ''

                        result[sn]['LICENSES'].append(license_info)
    return result


def parse_show_license_summary(output: str) -> list:
    # This function parses 'show license summary' output

    licenses = []
    lines = output.strip().split('\n')
    if 'Index' in lines[0]:
        # This is not expected for show license summary on modern devices, however it happens on 4500-x platform
        # call parse_show_license as the output matches it
        # import ipdb; ipdb.set_trace()
        return parse_show_license(output)

    # Skip header lines
    for line in lines[3:]:
        match = re.match(r'^\s*(\S+)\s+\(([^)]+)\)\s+(\d+)\s+(.+)$', line)
        if match:
            license = {
                'License': match.group(1),
                'Entitlement Tag': match.group(2),
                'Count': match.group(3),
                'Status': match.group(4).strip()
            }
            licenses.append(license)

    return licenses


def parse_show_license(output: str) -> list:
    # This function parses 'show license' output
    features = []
    current_feature = None

    for line in output.strip().split('\n'):
        index_match = re.match(r'Index (\d+)\s+Feature: (.+)', line)
        # import ipdb; ipdb.set_trace()
        if index_match:
            if current_feature:
                features.append(current_feature)
            current_feature = {
                'Index': index_match.group(1),
                'Feature': index_match.group(2)
            }
        elif current_feature:
            key_value_match = re.match(r'\s+(.+?): (.+)', line)
            if key_value_match:
                key = key_value_match.group(1)
                value = key_value_match.group(2)
                current_feature[key] = value

    if current_feature:
        features.append(current_feature)

    return features


def prepare_device_data(device_data_list: list) -> tuple:
    # This function prepares data gathered by process_device_data to a format suitable for saving in excel table
    all_columns = set()
    devices = {}

    def merge_device_info(info1: dict, info2: dict) -> dict:
        merged = info1.copy()
        for key, value in info2.items():
            if not merged.get(key) and value:
                merged[key] = value
        return merged

    for device_data in device_data_list:
        for row in device_data:
            all_columns.update(row.keys())
            device_key = (row['Device Name'], row.get('Serial Number', ''), row.get('License Name', ''))

            if device_key not in devices:
                devices[device_key] = row.copy()
            else:
                devices[device_key] = merge_device_info(devices[device_key], row)

    # Create final rows
    rows = list(devices.values())

    # Define priority columns
    priority_columns = [
        'Device Name',
        'Serial Number',
        'Product ID (PID)',
        'Parent Device Name',
        'Stack Role',
        'Software Version',
        'Software Image',
        'License Name',
        'License Type',
        'Confirmation Code',
        'License Count',
        'License Entitlement Tag',
        'License Period Left',
        'License Priority',
        'License Reservation Status',
        'License State',
        'License Status',
        'Uptime'
        ]

    # Sort columns with priority columns first, no other than priority columns expected, 
    # but if they present they will be added at the end
    other_columns = sorted(col for col in all_columns if col not in priority_columns)
    columns = priority_columns + other_columns

    # Ensure all rows have all columns (fill with empty string if missing)
    for row in rows:
        for col in columns:
            if col not in row:
                row[col] = ''

    # Convert rows to list format
    row_data = [[row.get(col, '') for col in columns] for row in rows]

    return columns, row_data


def process_device_data(logger: logging.Logger, cfg: dict, device_name: str, data: dict) -> list:
    # Function processes responses from a set of prepared dictionaries with different command results and returns a list
    # of dictionaries with merged data
    rows = []
    base_info = {
        'Device Name': device_name,
        'Software Version': data['show_version'].get('Software Version', ''),
        'Software Image': data['show_version'].get('Software Image', ''),
        'Uptime': data['show_version'].get('Uptime', ''),
        'Serial Number': data['show_version'].get('Serial Number', ''),
        'Product ID (PID)': '',
        'Stack Role': 'N/A',
        'Parent Device Name': None,
        'License Name': '',
        'License Type': '',
        'Confirmation Code': '',
        'License Count': '',
        'License Entitlement Tag': '',
        'License Period Left': '',
        'License Priority': '',
        'License Reservation Status': '',
        'License State': '',
        'License Status': '',
    }

    # Process license reservation data
    reservation_data = data.get('show_license_reservation', {})
    for sn, info in reservation_data.items():
        row = base_info.copy()
        row['Serial Number'] = sn
        row['Product ID (PID)'] = info.get('PID', '')
        row['Stack Role'] = info.get('TYPE', 'N/A')
        row['License Reservation Status'] = info.get('LICENSE_RESERVATION', '')
        row['Confirmation Code'] = info.get('CONFIRMATION_CODE', '')

        if row['Stack Role'] == 'Standby' or row['Stack Role'] == 'Member':
            row['Parent Device Name'] = device_name

        for license in info.get('LICENSES', []):
            license_row = row.copy()
            license_timeframe = f"{license.get('START_DATE', '')} to {license.get('END_DATE', '')}"
            if license_timeframe == " to ":
                license_timeframe = ""
            license_row.update({
                'License Name': license.get('LICENSE_NAME', ''),
                'License Type': license.get('LICENSE_TYPE', ''),
                'License Period Left': license_timeframe,
            })
            rows.append(license_row)

        if not info.get('LICENSES'):
            rows.append(row)

    # Process license summary data
    for license in data.get('show_license_summary', []):
        row = base_info.copy()
        row.update({
            'License Name': license.get('License', ''),
            'License Entitlement Tag': license.get('Entitlement Tag', ''),
            'License Count': license.get('Count', ''),
            'License Status': license.get('Status', ''),
        })
        rows.append(row)

    # Process detailed license data
    for license in data.get('show_license', []):
        row = base_info.copy()
        row.update({
            'License Name': license.get('Feature', ''),
            'License Type': license.get('License Type', ''),
            'License State': license.get('License State', ''),
            'License Period Left': license.get('Period left', ''),
            'License Priority': license.get('License Priority', ''),
            'License Count': license.get('License Count', ''),
        })
        rows.append(row)

    # If no license data was found, add at least one row with base info
    if not rows:
        rows.append(base_info)

    return rows


def process_device_commands(logger: logging.Logger, cfg: dict, device: str, cmd_list: dict, type: str = 'cisco_ios') -> dict:
    # interrogate device and get serial/mac/license data
    # check for reverse DNS entry

    dns_name = None
    try:
        dns_name = gethostbyaddr(device)[0]
    except:
        pass
    if dns_name and not re.search(r'(es|mp|vi|bl|sp|lf)\d{3}', dns_name):
        logger.info(f'{device} - [yellow bold]Not supported device type![/]')
        return {device: 'Not supported device type'}
    elif dns_name:
        device = dns_name

    output = {}
    # with console.status(f"Interrogating [bright_green]{device}[/]...", spinner="dots12"):
    username = session.auth[0]
    password = session.auth[1]
    conn = ConnLogOnly(
        device_type=type, host=device, username=username, password=password, secret='', log_level=cfg["log_level_str"]
        )
    if conn is None:
        # console.print(f'{device} - [yellow bold]Unable to connect![/]')
        logger.info(f'{device} - Unable to connect!')
        return {}

    for cmd_key, funcs in cmd_list.items():
        data = conn.send_command(f"{cmd_key.replace('_', ' ')}\n", auto_find_prompt=True)
        # funcs[0] - parse function, funcs[1] - create tables
        output[cmd_key] = funcs[0](data)

    conn.disconnect()
    return output


def device_query(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide IP address(es) or hostname(es)
    Validates user input
    Works on the input calling other functions
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """
    cmd_list = {
        "show_version": (parse_show_version, create_show_version_table,),
        "show_license_reservation": (parse_show_license_reservation, create_license_reservation_tables,),
        "show_license_summary": (parse_show_license_summary, create_license_summary_table,),
        "show_license": (parse_show_license, create_show_license_table,),
    }

    colors = get_global_color_scheme(cfg)

    logger.info("User input phase")
    console.print(
        "\n"
        f"[{colors['description']}]Please provide a list of IP addresses or hostnames one per line[/]\n"
        f"[{colors['description']}]Empty input line starts the process[/]\n"
        f"[{colors['header']}]Example:[/]\n"
        f"[{colors['success']} {colors['bold']}]134.162.104.110[/]\n"
        f"[{colors['success']} {colors['bold']}]aucicvi660[/]\n"
    )

    devices = []
    while True:
        search_input = read_user_input(logger, "").strip()
        if search_input == "":
            break

        # Check if input looks like an IP address or subnet
        if "/" not in search_input and re.match(ip_regexp, search_input):
            # IP address provided
            try:
                ip = ipaddress.ip_address(search_input)
            except ValueError:
                logger.info(
                    f"User input - Input not matching IP address: {search_input}"
                )
                console.print(
                    f"[{colors['error']}]Invalid IP format.[/]\n"
                    f"[{colors['description']}]Enter a valid IP (e.g. 192.168.1.10)[/]"
                )
                continue
            else:
                if (
                    ip.is_multicast
                    or ip.is_unspecified
                    or ip.is_reserved
                    or ip.is_link_local
                ):
                    logger.info(f"User input - Invalid IP address type: {search_input}")
                    console.print(
                        f"[{colors['error']}]Invalid IP - multicast, broadcast, and reserved IPs are excluded.[/]\n"
                        f"[{colors['description']}]Enter a valid non-reserved IP (e.g. 192.168.1.10)[/]"
                    )
                    continue
                devices.append(search_input)
                continue
        else:
            if not is_fqdn(search_input):
                logger.info(f"User input - Invalid FQDN: {search_input}")
                console.print(
                    f"[{colors['error']}]Please use proper hostname format or full FQDN.[/]\n"
                    f"[{colors['description']}]Enter a valid hostname (e.g. aucicvi660 or aucicvi660.net-equip.shell.net)[/]"
                )
            else:
                devices.append(search_input)
                continue

    if devices and len(devices) > 0:
        log_value = ", ".join([str(device) for device in devices])
        # log_value = search_input.replace(",", " ")
        logger.info(f"User input - {log_value}")

        # One liner remove duplicates from net_addresses
        devices = list(dict.fromkeys(devices))
    else:
        return

    # start = perf_counter()

    results = {}

    with console.status(f"[{colors['description']}]Talking to devices...[/]", spinner="dots12"):
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                device:
                executor.submit(
                    process_device_commands,
                    logger,
                    cfg,
                    device,
                    cmd_list,
                )
                for device in devices
            }
            results = {device: future.result() for device, future in futures.items()}

    for hostname, device_data in results.items():
        # import ipdb; ipdb.set_trace()
        print_data = []
        for key in device_data.keys():
            # key will be equal to hostname if there was an error processing device
            if key == hostname:
                print_data.append(create_device_error_table(hostname, cfg["theme"]))
                continue
            # cmd_list has tuple with functions and function 1 used to process data and create table object(s)
            tables = cmd_list[key][1](device_data[key], hostname, cfg['theme'])
            if tables and isinstance(tables, list):
                for t in tables:
                    if t:
                        print_data.append(t)
            elif tables:
                print_data.append(tables)

        # Print device data in the panel
        if len(print_data) > 0:
            print_multi_table_panel(print_data, f'Device {hostname.upper()}', cfg['theme'])

    if cfg["auto_save"]:
        processed_data = []
        # Get all gathered data processed and then prepared for saving in the report 
        for hostname, device_data in results.items():
            processed_data.append(process_device_data(logger, cfg, hostname, device_data))

        columns, data_to_save = prepare_device_data(processed_data)

        queue_save(
            logger,
            cfg["report_filename"],
            columns,
            data_to_save,
            sheet_name="Device Data",
            index=False,
            force_header=True,
        )


def print_multi_table_panel(tables, title, color_scheme="default"):
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"

    colors = COLOR_SCHEMES[color_scheme]

    # Create a Group of tables if tables is a list
    if isinstance(tables, list):
        group = Group(*tables)
    else:
        group = tables

    # Wrap the Group in a Panel
    panel = Panel(group, title=title, border_style=colors["title"], title_align="left", padding=1, expand=False)

    # Print the panel
    console.print(panel)


def create_show_version_table(data: list, hostname: str, color_scheme="default"):
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"

    colors = COLOR_SCHEMES[color_scheme]

    if data is None or len(data) == 0:
        return None

    table = Table(title="General Information", show_header=True, header_style=colors["header"], box=box.MINIMAL, title_justify="left")
    table.add_column("Hostname", style=colors["hostname"])
    table.add_column("Serial", style=colors["sn"])
    table.add_column("Uptime", style=colors["date"])
    table.add_column("Software Version", style=colors["license_type"])
    table.add_column("Software Image", style=colors["description"], overflow='fold')

    table.add_row(
        hostname.upper(),
        data.get("Serial Number", 'N/A'),
        data.get("Uptime", 'N/A'),
        data.get("Software Version", 'N/A'),
        data.get("Software Image", 'N/A')
        )
    return table


def create_device_error_table(hostname: str, color_scheme="default"):
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"

    colors = COLOR_SCHEMES[color_scheme]

    table = Table(title="General Information", show_header=True, header_style=colors["header"], box=box.MINIMAL, title_justify="left")
    table.add_column("Hostname", style=colors["hostname"])
    table.add_column("Information", style=colors["sn"])

    table.add_row(
        hostname.upper(),
        "Unable to access device",
        )
    return table


def create_show_license_table(data: list, hostname: str, color_scheme="default"):
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"

    colors = COLOR_SCHEMES[color_scheme]

    if data is None or len(data) == 0:
        return None

    table = Table(title="License Information", show_header=True, header_style=colors["header"], box=box.MINIMAL, title_justify="left")
    table.add_column("Feature", style=colors["feature"])
    table.add_column("Attribute", style=colors["feature"])
    table.add_column("Value", style=colors["value"])

    for feature in data:
        table.add_row(feature['Feature'], '', '')
        for key, value in feature.items():
            if key not in ['Index', 'Feature']:
                table.add_row('', key, value)
    return table


def create_license_summary_table(data: list, hostname: str, color_scheme="default"):
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"

    colors = COLOR_SCHEMES[color_scheme]

    if data is None or len(data) == 0:
        return None

    if 'Index' in data[0]:
        # looks like an old device calling standard create_show_license_table
        return create_show_license_table(data, hostname, color_scheme)

    table = Table(title="License Summary", show_header=True, header_style=colors["header"], box=box.MINIMAL, title_justify="left")
    table.add_column("License", style=colors["license"])
    table.add_column("Entitlement Tag", style=colors["tag"])
    table.add_column("Count", style=colors["count"])
    table.add_column("Status", style=colors["status"])

    for license in data:
        table.add_row(
            license['License'],
            license['Entitlement Tag'],
            license['Count'],
            license['Status']
        )

    return table


def create_license_reservation_tables(data: dict, hostname: str, color_scheme: str = "default"):

    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"

    colors = COLOR_SCHEMES[color_scheme]

    if data is None or len(data) == 0:
        return None

    license_reservation = "UNKNOWN"
    # Process all devices in data and print information on the rest of the devices
    # Create and print the device information table
    device_table = Table(title="Overall License Information", show_header=True, header_style=colors["title"], box=box.MINIMAL, title_justify="left")
    device_table.add_column("Hostname", style=colors["hostname"], no_wrap=True)
    device_table.add_column("Serial Number", style=colors["sn"], no_wrap=True)
    device_table.add_column("Type", style=colors["type"])
    device_table.add_column("PID", style=colors["pid"])
    device_table.add_column("Reservation Status", style=colors["status"])
    device_table.add_column("Reservation Date", style=colors["date"])
    device_table.add_column("Export Controlled", style=colors["export"])
    device_table.add_column("Confirmation Code", style=colors["code"])
    device_table.add_column("License Reservation", style=colors["reserved"])

    for sn, info in data.items():
        device_table.add_row(
            hostname.upper(),
            sn,
            info['TYPE'],
            info['PID'],
            info.get('RESERVATION_STATUS', 'N/A'),
            info.get('RESERVATION_DATE', 'N/A'),
            info.get('EXPORT_CONTROLLED', 'N/A'),
            info.get('CONFIRMATION_CODE', 'N/A'),
            info.get('LICENSE_RESERVATION', license_reservation)
        )
    # # Create and print a license table for each device
    license_table = Table(title="Extended License Information", show_header=True, header_style=colors["title"], box=box.MINIMAL, title_justify="left")
    license_table.add_column("Serial", style=colors["sn"], no_wrap=True)
    license_table.add_column("Type", style=colors["license_type"], no_wrap=True)
    license_table.add_column("License Name", style=colors["license_name"], no_wrap=True)
    license_table.add_column("Full Name", style=colors["license_full"])
    license_table.add_column("Description", style=colors["description"])
    license_table.add_column("Total Reserved", style=colors["reserved"])
    license_table.add_column("Enforcement Type", style=colors["enforcement"])
    license_table.add_column("Authorization Type", style=colors["auth_type"])
    license_table.add_column("License Type", style=colors["license_type"])
    license_table.add_column("Start Date", style=colors["start_date"])
    license_table.add_column("End Date", style=colors["end_date"])
    license_table.add_column("Term Count", style=colors["term_count"])
    for sn, info in data.items():
        for license in info['LICENSES']:
            license_table.add_row(
                sn,
                info['TYPE'],
                license['LICENSE_NAME'],
                license['LICENSE_FULL_NAME'],
                license['LICENSE_DESCRIPTION'],
                license['TOTAL_RESERVED'],
                license.get('ENFORCEMENT_TYPE', 'N/A'),
                license.get('AUTHORIZATION_TYPE', 'N/A'),
                license['LICENSE_TYPE'],
                license.get('START_DATE', 'N/A'),
                license.get('END_DATE', 'N/A'),
                license['TERM_COUNT']
            )

    if license_table.row_count == 0:
        license_table = None
    return [device_table, license_table]


def create_table(
    logger: logging.Logger,
    title: str,
    columns: list,
    data: list[list],
    color_scheme: str = "default",
    title_style: str = "bold yellow",
    box: box = box.MINIMAL,
    **kwargs
) -> Table:
    """
    Creates a Rich table with the provided parameters.

    @param    logger(Logger): logger instance.
    @param    title (str): The title of the table.
    @param    columns (list[str]): A list of column names.
    @param    data (list[list]): A list of rows, where each row is a list of data values.
    @param    color_scheme (str, optional): The color scheme to use. Defaults to "default".
    @param    title_style (str, optional): The style for the table title. Defaults to "bold yellow".
    @param    box (box, optional): The box style for the table. Defaults to box.MINIMAL.

    @return    Table: The created Rich table.
    """

    title = title.upper()

    logger.debug(f"Table - title = {title} columns = {len(columns)} rows = {len(data)}")

    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"

    colors = COLOR_SCHEMES[color_scheme]
    color_cycle = cycle(colors.values())

    table = Table(title=title, title_style=colors.get("title", title_style), box=box, **kwargs)
    for column in columns:
        table.add_column(
            column, justify="left", style=next(color_cycle, color_cycle), no_wrap=False
        )

    for row in data:
        table.add_row(*row)

    return table


def print_table_data(
    logger: logging.Logger, cfg: dict, data: dict, prefix: dict = {}, suffix: dict = {}
) -> None:
    """
    Prints data using keys as column names, can use prefix/suffix dictionary to add additional information to title (main keys)
    keys in data should match keys in suffix/prefix
    @param data(dict)
    @param prefix(dict)
    @param suffix(dict)

    @return None
    """
    if len(data) == 0:
        console.print("No data to display")
        return

    tables = []
    for key, value_list in data.items():
        # Capitalize the first letter of the key
        section_title = key
        # Add prefix and suffix to the section title if available
        prefix_text = prefix.get(key, "")
        suffix_text = suffix.get(key, "")
        section_title = f"{prefix_text} {section_title} {suffix_text}"
        section_title.upper()
        # Define colums
        columns = []
        # Define table data
        table_data = []

        # Dont do anything if dict has no values
        if len(value_list) == 0:
            continue

        # Since we get list of dict objects - each has same keys() which we can use as column names

        for name in value_list[0].keys():
            columns.append(name.upper())

        for record in value_list:
            table_data.extend([record.values()])

        tables.append(create_table(logger, section_title, columns, table_data, cfg["theme"], title_justify="left"))
        # console.print(table)

    print_multi_table_panel(tables, '', cfg['theme'])


def exit_now(logger: logging.Logger, cfg: dict = {}, exit_code: int = 0, message: str = '') -> None:
    """
    Gracefully exits from application

    @param logger(Logger): logger instance.
    @param exit_code(int): exit code =0 clean exit, >0 means an error.

    @return: exit_code
    """
    colors = get_global_color_scheme(cfg)

    if worker_thread:
        logger.info("Closing report file...")
        console.print(f"[{colors['success']}]Closing report file...[/]")
        wait_for_all_saves()

    if not exit_code:
        console.print(f"[{colors['success']}]Have a nice day![/] :smiley:")
        logger.info("Terminating by user request - Have a nice day!")
    else:
        console.print(f"[{colors['error']}]{message}[/]")
        logger.info("Abnormal termination - Hoping for a patch!")

    exit(exit_code)


def make_api_call(logger: logging.Logger, cfg: dict, endpoint: str, uri: str) -> any:
    """
    Performs Infoblox API requests, handles exceptions and validates that response.content is a valid json object
    in case of API errors logs error and terminates program execution

    @return: response(Response): Returns complete response without parsing for data
    """

    logger.info(f"Performing API request - URL: {endpoint}{uri}")

    try:
        response = session.get(f"{endpoint}{uri}", verify=False)
        response.raise_for_status()

    except (Timeout, ConnectionError) as e:
        logger.error(f"API Error - {e.response.status_code} - {e.response.text}")
        exit_now(logger, exit_code=1, message=f"API Error - {e.response.text}")

    except (HTTPError, RequestException, MissingSchema) as e:
        if response.status_code == 400:
            logger.info(f"API - Missing data - {e.response.text}")
        elif response.status_code == 401:
            logger.error(f"API Error - Authentication error - {e.response.text}")
            exit_now(logger, exit_code=1, message=f'Authentication error - verify credentials - {e.response.text}')
        else:
            logger.error(f"API Error - {e}")
            exit_now(logger, exit_code=1, message=f'API Error - {e}')
        logger.debug(f"API response: {response.content}")

        try:
            json.loads(response.content)
        except json.JSONDecodeError as e:
            logger.error(f"API Error - Failed to parse JSON response - {e}")
            exit_now(logger, exit_code=1, message='Failed to parse JSON response|Check API URL!')

    return response


def do_fancy_request(
    logger: logging.Logger,
    cfg: dict,
    message: str,
    endpoint: str,
    uri: str,
    spinner: str = "dots12",
) -> any:
    """
    Prepares shows message, spinner and performs make_api_call
    Validates response status

    @param logger(Logger): logger instance.

    @return: content(response.content) or None if request has error
    """

    def execute_request():
        response = make_api_call(logger, cfg, endpoint, uri)
        if response.ok:
            return response.content
        else:
            return None

    if spinner:
        # If spinner is not None, use the context manager with spinner
        with console.status(status=message, spinner=spinner):
            return execute_request()
    else:
        # If spinner is None, execute the request directly
        return execute_request()


def process_data(logger: logging.Logger, type: str, content: str) -> dict:
    """
    Process raw information according to 'type' and return data dict to be used in print/save

    @param logger(Logger): logger instance.
    @param type(str): a key to be used in processing logic and as a key in the returned
        dictionary(unless other keys required by processing logic)
    @param content(json string): Response.content returned by do_fancy_call

    @return: process_data(dict) or None: Contains keys holding processed information
        or returns {} if no data gathered
    """

    logger.info(f"Processing data - {type.upper()}")

    logger.debug(f"Processing data {type.upper()} content: {content}")

    try:
        raw_data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON response - {e}")
        exit_now(logger, exit_code=1, error_message="Failed to parse JSON response|Check API URL!")

    # If data present, process it and return corresponding dict
    if len(raw_data) == 0:
        return {}

    data = raw_data[0]
    processed_data = {}
    if type == "ip":
        processed_data = {"general": [], "extra": []}

        # General IP information output
        processed_data["general"].append(
            {
                "network": data.get("network"),
                "ip": str(data.get("_ref")).split(":")[1],
                "name": ",".join(data.get("names")),
                "status": data.get("status"),
            }
        )

        # Extra IP information output
        if data.get("lease_state"):
            lease_state = data.get("lease_state")
        else:
            lease_state = ""

        if data.get("types") and len(data.get("types")) != 0:
            types = data.get("types")
        else:
            types = ""

        if data.get("mac_address") and len(data.get("mac_address")) != 0:
            mac_address = data.get("mac_address")
        else:
            mac_address = ""

        # Only print additional table if it has some data
        if len(mac_address + "".join(types) + lease_state) > 0:

            processed_data["extra"].append(
                {
                    "lease state": lease_state,
                    "record type": ",".join(types),
                    "mac": mac_address,
                }
            )

    elif type == "location_keyword":
        processed_data = {"location": []}
        processed_data["location"] = [
            {"network": location.get("network"), "comment": location.get("comment")}
            for location in raw_data
            if location.get("network")
        ]
    elif type.startswith("location_"):
        # extract sitecode from type argument
        sitecode = type.split("_")[1].lower()
        processed_data = {"location": []}
        processed_data["location"] = [
            {"network": location.get("network"), "comment": location.get("comment")}
            for location in raw_data
            if location.get("network")
            and len(location.get("comment", "").split(";")) > 1
            and location.get("comment", "").split(";")[1].strip().lower() == sitecode
        ]
    elif type == "fqdn":
        processed_data = {"fqdn": []}
        processed_data["fqdn"] = [
            {"ip": f"{fqdn.get('ipv4addr')}", "name": f"{fqdn.get('name')}"}
            for fqdn in raw_data
            if fqdn.get("ipv4addr")
        ]
    elif type == "general":
        processed_data = {"general": []}
        # General subnet information
        if data and len(data) > 0:
            processed_data["general"] = [
                {
                    "subnet": data.get("network", ""),
                    "description": data.get("comment", ""),
                }
            ]

    elif type == "DNS records":
        # DNS Information
        processed_data = {"DNS records": []}
        processed_data["DNS records"] = [
            {
                "IP address": record.get("ip_address"),
                "A Record": ", ".join(record.get("names", "")),
            }
            for record in raw_data
        ]

    elif type == "network options":

        if data and len(data) > 0:
            processed_data = {"DHCP members": [], "DHCP options": []}
            # Network DHCP Members Information
            dhcp_members_data = data.get("members", [])
            dhcp_options_data = data.get("options", [])
            if len(dhcp_members_data) > 0:
                processed_data["DHCP members"] = [
                    {"IP Address": member.get("ipv4addr"), "name": member.get("name")}
                    for member in dhcp_members_data
                ]
            if len(dhcp_options_data) > 0:
                # Network DHCP Options Information output
                processed_data["DHCP options"] = [
                    {
                        "name": option.get("name"),
                        "num": str(option.get("num")),
                        "value": option.get("value"),
                        "vendor class": option.get("vendor_class"),
                        "use option": str(option.get("use_option")),
                    }
                    for option in dhcp_options_data
                ]

    elif type == "DHCP range":
        processed_data = {"DHCP range": []}
        # Network DHCP Range Information output
        processed_data["DHCP range"] = [
            {
                "network": range.get("network"),
                "start address": range.get("start_addr"),
                "end address": range.get("end_addr"),
            }
            for range in raw_data
        ]
    elif type == "DHCP failover":
        processed_data = {"DHCP failover": []}
        # Network DHCP Failover Association Information output
        processed_data["DHCP failover"] = [
            {"dhcp failover": dhcp_failover.get("failover_association")}
            for dhcp_failover in raw_data
        ]
    elif type == "fixed addresses":
        processed_data = {"fixed addresses": []}
        # Network DHCP Fixed Addresses Information output
        processed_data["fixed addresses"] = [
            {
                "IP address": addr_obj.get("ipv4addr"),
                "name": addr_obj.get("name"),
                "MAC": addr_obj.get("mac"),
            }
            for addr_obj in raw_data
        ]

    return processed_data


def ip_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide IP address(es)
    Validates user input
    Calls do_fancy_request
    Calls process_ip_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """

    colors = get_global_color_scheme(cfg)

    logger.info("Request Type - IP Information")
    console.print(
        "\n"
        f"[{colors['description']}]Please provide IP address or a list of IP addresses one per line, tool will request API and return detailed information,\n"
        f"such as its hostname, location, and network configuration[/]\n"
        f"[{colors['description']}]Empty input line starts the process[/]\n"
        f"[{colors['header']}]Example:[/]\n"
        f"[{colors['success']} {colors['bold']}]134.162.104.110[/]\n"
        f"[{colors['success']} {colors['bold']}]134.143.104.145[/]\n"
    )
    search_input = "none"
    ip_addresses = None
    while True:
        search_input = read_user_input(logger, "").strip()
        if search_input == "":
            break

        # Check if input looks like an IP address or subnet
        if "/" not in search_input and re.match(ip_regexp, search_input):
            # IP address provided
            try:
                ip = ipaddress.ip_address(search_input)
            except ValueError:
                logger.info(
                    f"User input - Input not matching IP address: {search_input}"
                )
                console.print(
                    f"[{colors['error']}]Invalid IP format.[/]\n"
                    f"[{colors['info']}]Enter a valid IP (e.g. 192.168.1.10)[/]"
                )
                continue
            else:
                if (
                    ip.is_multicast
                    or ip.is_unspecified
                    or ip.is_reserved
                    or ip.is_link_local
                ):
                    logger.info(f"User input - Invalid IP address type: {search_input}")
                    console.print(
                        f"[{colors['error']}]Invalid IP - multicast, broadcast, and reserved IPs are excluded.[/]\n"
                        f"[{colors['info']}]Enter a valid non-reserved IP (e.g. 192.168.1.10)[/]"
                    )
                    continue
                if ip_addresses is None:
                    ip_addresses = []
                ip_addresses.append((ip, None))
                continue
        else:
            logger.info(
                f"User input - Input not matching IP address: {search_input}"
            )
            console.print(
                f"[{colors['error']}]Invalid IP format.[/]\n"
                f"[{colors['info']}]Enter a valid IP (e.g. 192.168.1.10)[/]"
            )            

    if ip_addresses and len(ip_addresses) > 0:
        log_value = ", ".join([str(ip) for ip, _ in ip_addresses])
        # log_value = search_input.replace(",", " ")
        logger.info(f"User input - {log_value}")

        # One liner remove duplicates from net_addresses
        ip_addresses = list(dict.fromkeys(ip_addresses))
    else:
        return

    start = perf_counter()

    # Keep all provided input in a set, allows to get rid of duplicates
    processed_data = {}

    # prepare dict for threaded execution
    req_urls = {}
    for ip, _ in ip_addresses:
        req_urls[ip] = (
            f"ipv4address?ip_address={ip}&_return_fields=network,names,status,types,lease_state,mac_address"
        )

    # Request general network information
    with ThreadPoolExecutor() as executor:
        with console.status(status=f"[{colors['description']}]Fetching IP information...[/]"):
            futures = {
                ip: executor.submit(
                    do_fancy_request,
                    logger=logger,
                    cfg=cfg,
                    message="",
                    endpoint=cfg["api_endpoint"],
                    uri=uri,
                    spinner=None,
                )
                for ip, uri in req_urls.items()
            }
            results = {ip: future.result() for ip, future in futures.items()}

    for ip, response in results.items():
        if response and len(response) > 0:
            # process_data if not empty has 'general' and 'extra' keys with IP data
            processed_data[ip] = process_data(logger, type="ip", content=response)
            if processed_data[ip] and len(processed_data[ip].get("general")) > 0:
                try:
                    ip_addresses.remove((ip, None))
                except KeyError:
                    pass
                ip_addresses.append((ip, True))

    end = perf_counter()
    logger.info(f"Search took {round(end-start, 3)} seconds!")
    console.print(
        f"[{colors['description']}]Request Type - IP Information - Search took [{colors['success']}]{round(end-start, 3)}[/] seconds![/]"
    )

    for ip, status in ip_addresses:
        if not status:
            console.print(
                f"[{colors['success']} {colors['bold']}]{ip}[/] - [{colors['error']}]No data received[/]"
            )

    save_data_all = []

    for ip in processed_data:

        logger.debug(
            f"Request Type - IP Information - processed data {processed_data[ip]}"
        )

        save_data, save_data_general, save_data_extra = [], [], []
        for ip_data in processed_data[ip]["general"]:
            save_data_general.append([value for value in ip_data.values()])
        for ip_data in processed_data[ip]["extra"]:
            save_data_extra.append([value for value in ip_data.values()])
        # Combine two arrays
        # Iterate over the rows of save_data_general and save_data_extra simultaneously using zip()
        # If save_data_extra has fewer rows than save_data_general, we add empty lists ([]) to save_data_extra to make their lengths equal
        # For each pair of rows (row1 from save_data_general and row2 from save_data_extra), we check if row2 has the same length as row1:
        # If they have the same length, we concatenate row1 and row2 as is.
        # If row2 is shorter than row1, we concatenate row2 with a list of empty strings ([''] * (len(row1) - len(row2))) to make their lengths equal before concatenating with row1.
        # This ensures that if save_data_extra has fewer elements in a row compared to save_data_general, the missing elements are filled with empty strings in the resulting save_data list
        save_data = [
            row1
            + (
                row2
                if len(row2) == len(row1)
                else row2 + [""] * (len(row1) - len(row2))
            )
            for row1, row2 in zip(
                save_data_general,
                save_data_extra
                + [[] for _ in range(len(save_data_general) - len(save_data_extra))],
            )
        ]
        save_data_all.extend(save_data)

    columns = [
        "Subnet",
        "IP",
        "Name",
        "Status",
        "Lease State",
        "Record Type",
        "MAC",
    ]

    # Print IP information in a single table
    print_data = [dict(zip(columns, row)) for row in save_data_all]
    print_table_data(
        logger,
        cfg,
        {"IP": print_data},
        suffix={"IP": "Information"},
    )

    # Saving data automatically unless user requested not to (relies on global auto_save flag)
    if cfg["auto_save"]:
        missing_ip_addresses = []
        for ip, status in ip_addresses:
            if not status:
                missing_ip_addresses.append(ip)
        if len(missing_ip_addresses) > 0:
            missed_ip_data = [
                [str(ip), "No Information"] for ip in missing_ip_addresses
            ]
            # Saving IP Data with missed IPs first
            queue_save(
                logger,
                cfg["report_filename"],
                ["IP", "Status"],
                missed_ip_data,
                sheet_name="IP Data",
                index=False,
                force_header=True,
            )
        # Saving IP Data with found IP information
        if len(save_data_all) > 0:
            queue_save(
                logger,
                cfg["report_filename"],
                columns,
                save_data_all,
                sheet_name="IP Data",
                index=False,
                force_header=True,
            )

    return


def fqdn_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide FQDN string
    Validates user input
    Calls do_fancy_request
    Calls process_fqdn_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """
    colors = get_global_color_scheme(cfg)

    logger.info("Request Type - FQDN Search - DNS A records")

    console.print(
        "\n"
        f"[{colors['description']}]Type in just a part of the name or complete FQDN name(not less than 3 chars)\n"
        f"Request fetches DNS A records matching or containing prefix, short hostname or full FQDN\n"
        f"Request has a limit of [{colors['error']} {colors['bold']}]1000[/] records[/]\n"
        f"[{colors['header']}]Examples:[/]\n"
        f"[{colors['success']}][{colors['bold']}]'aucicbst'[/] fetches records starting with [{colors['white']} {colors['bold']}]aucicbst[/] prefix\n"
        f"[{colors['bold']}]'aucicbstwc010'[/] fetches record for the device\n"
        f"[{colors['bold']}]'aucicbstwc010.net-equip.shell.net'[/] fetches record for the device[/]\n"
    )

    fqdn = read_user_input(
        logger, "Enter the device name(fqdn or short prefix): "
    ).lower()

    logger.info(f"User input - FQDN Search - {fqdn}")

    if not is_fqdn(fqdn):
        logger.info(f"User input - FQDN Search - Incorrect FQDN/prefix - {fqdn}")
        console.print(f"[{colors['error']}]Incorrect FQDN/prefix[/]")
        return

    if len(fqdn) < 3:
        logger.info("User input - FQDN Search - Prefix is less than 3 chars")
        console.print(f"[{colors['error']}]Please use longer prefix(at least 3 characters)[/]")
        return

    uri = f"search?fqdn~={fqdn}&_max_results=1000"
    data = do_fancy_request(
        logger,
        cfg,
        message=f"[{colors['description']}]Fetching data for [{colors['header']}]{fqdn}[/]...[/]",
        endpoint=cfg["api_endpoint"],
        uri=uri,
    )

    processed_data = {}

    if data and len(data) > 0:
        # process_data if not empty has 'fqdn' key with found A DNS records
        processed_data = process_data(logger, type="fqdn", content=data)

    if len(processed_data) == 0:
        logger.info("Request Type - FQDN Search - No information received")
        console.print(f"[{colors['error']}]No information received[/]")
        logger.debug(f"Request Type - FQDN Search - raw data {data}")
        return

    print_table_data(logger, cfg, processed_data, suffix={"general": "Search Results"})
    logger.debug(f"Request Type - FQDN Search - processed data {processed_data}")

    # Saving data automatically unless user requested to not to(relies on global auto_save flag)
    if cfg["auto_save"]:
        columns = ["IP Address", "Device Name"]
        save_data = []
        for fqdn in processed_data["fqdn"]:
            save_data.append([value for value in fqdn.values()])

        queue_save(
            logger,
            cfg["report_filename"],
            columns,
            save_data,
            sheet_name="FQDN Data",
            index=False,
            force_header=True,
        )
    return


def location_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide FQDN string
    Validates user input
    Calls do_fancy_request
    Calls process_site_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """
    colors = get_global_color_scheme(cfg)

    logger.info("Request Type - Search for site subnet records")

    console.print(
        "\n"
        f"[{colors['description']}]Type in location site code to obtain a list of registered [{colors['bold']}]subnets[/]\n"
        f"[{colors['description']}]Supported site code format: [{colors['success']} {colors['bold']}]XXX, XXXXXXX, XXX-XX\\[XX][/]\n"
        f"[{colors['description']}]Request has a limit of [{colors['error']} {colors['bold']}]1000[/] records[/]\n"
        f"[{colors['header']} {colors['bold']}]Examples:[/]\n"
        f"[{colors['success']} {colors['bold']}]CIC[/] fetches subnets for [{colors['warning']} {colors['bold']}]Chinchilla site[/]\n"
        f"[{colors['success']} {colors['bold']}]WND-RYD[/] fetches subnets for [{colors['warning']} {colors['bold']}]Wandoan site[/]\n"
        "\n"
        f"[{colors['description']}]Type in '[{colors['error']} {colors['bold']}]+[/]' as a first symbol followed by arbitrary keyword(cannot have spaces)[/]\n"
        f"[{colors['header']} {colors['bold']}]Examples:[/]\n"
        f"[{colors['error']} {colors['bold']}]+[/][{colors['success']} {colors['bold']}]CNBEJWTCMP610[/] [{colors['description']}]fetches subnets with [{colors['bold']}]CNBEJWTCMP610[/] in description[/]\n"
        f"[{colors['error']} {colors['bold']}]+[/][{colors['success']} {colors['bold']}]PRJ18[/] [{colors['description']}]fetches subnets with [{colors['bold']}]PRJ18[/] in description[/]\n"
    )

    raw_input = read_user_input(
        logger,
        f"Enter [{colors['success']} {colors['bold']}]location code[/] or '[{colors['error']} {colors['bold']}]+[/]'[{colors['success']} {colors['bold']}]keyword[/]: "
        ).lower()

    logger.info(f"User input - {raw_input}")

    search_term = ""
    search_type = ""
    prefix = {}
    suffix = {}
    if raw_input.startswith("+"):
        if re.match(r"^[a-zA-Z0-9_]*$", raw_input[1:]):
            search_term = raw_input[1:]
            logger.info(f"User input - Keyword search for {search_term}")
            search_type = "keyword"
        else:
            logger.info(f"User input -  Incorrect input {raw_input}")
            console.print(f"[{colors['error']}]Incorrect input provided[/]")
            return
    else:
        if is_valid_site(raw_input):
            search_term = raw_input
            # to handle in the process_data sitecodes
            search_type = raw_input
            prefix.update({"location": f"{search_term.upper()}"})
            suffix.update({"location": "Subnets"})
            logger.info(f"User input - Sitecode search for {search_term}")
        else:
            logger.info(f"User input -  Incorrect site code {raw_input}")
            console.print(f"[{colors['error']}]Incorrect site code[/]")
            return

    if len(search_term) == 0:
        logger.info("User input -  Empty input")
        console.print(f"[{colors['error']}]Incorrect input provided[/]")
        return

    uri = f"network?comment:~={search_term}&_max_results=1000"
    data = do_fancy_request(
        logger,
        cfg,
        message=f"[{colors['description']}]Fetching data for [{colors['header']}]{search_term.upper()}[/]...[/]",
        endpoint=cfg["api_endpoint"],
        uri=uri,
    )

    processed_data = {}
    if data and len(data) > 0:
        # process_data if not empty has 'location' key with subnet data
        processed_data = process_data(
            logger, type=f"location_{search_type}", content=data
        )

    if len(processed_data.get("location", "")) == 0:
        logger.info("Request Type - Location Information - No information received")
        console.print(f"[{colors['error']}]No information received[/]")
        return

    print_table_data(
        logger,
        cfg,
        processed_data,
        prefix=prefix,
        suffix=suffix,
    )
    logger.debug(
        f"Request Type - Location Information - processed data {processed_data}"
    )

    if cfg["auto_save"]:
        columns = ["Subnet", "Description"]
        save_data = []
        for subnet in processed_data["location"]:
            save_data.append([value for value in subnet.values()])

        # append_df_to_excel(
        queue_save(
            logger,
            cfg["report_filename"],
            columns,
            save_data,
            sheet_name="Subnet Lookup",
            index=False,
            force_header=True,
        )

    return


def subnet_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Requests user to provide network IP
    Validates user input
    Calls do_fancy_request for general, dns_records, network_options,
        dhcp_range, dhcp_failover, fixed_address data
    Calls process_network_data
    Prints data if present
    Saves data if auto_save enabled

    @param logger(Logger): logger instance.

    @return: None
    """
    colors = get_global_color_scheme(cfg)

    logger.info("Request Type - Subnet Information")

    console.print(
        "\n"
        f"[{colors['description']}]Enter a network addresses in the format 'x.x.x.x\\[/x]' one subnet per line[/]\n"
    )

    net_addresses = []
    while True:
        search_input = read_user_input(logger, "").strip()
        if search_input == "":
            break

        # Check if input looks like an IP address or subnet
        if "/" not in search_input and re.match(ip_regexp, search_input):
            # IP address provided
            try:
                ip = ipaddress.ip_address(search_input)
            except ValueError:
                logger.info(
                    f"User input - Input not matching IP address: {search_input}"
                )
                console.print(
                    f"[{colors['error']}]Invalid IP format.[/]\n"
                    f"[{colors['info']}]Enter a valid IP (e.g. 192.168.1.10)[/]"
                )
                continue
            else:
                if (
                    ip.is_unspecified
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_loopback
                ):
                    logger.info(f"User input - Invalid IP address type: {search_input}")
                    console.print(
                        f"[{colors['error']}]Invalid IP - multicast, broadcast, and reserved IPs are excluded.[/]\n"
                        f"[{colors['info']}]Enter a valid non-reserved IP[/]"
                    )
                    continue
                net_addresses.append(ip)
                continue
        else:
            try:
                net = ipaddress.ip_network(search_input)
            except ValueError:
                logger.info(
                    f"User input - Input not matching valid IP/MASK: {search_input}"
                )
                console.print(
                    f"[{colors['error']}]Invalid IP format.[/]\n"
                    f"[{colors['info']}]Enter a valid IP/MASK (e.g. 192.168.1.10/24)[/]"
                )
                continue
            else:
                if (
                    net.is_unspecified
                    or net.is_reserved
                    or net.is_multicast
                    or net.is_loopback
                ):

                    logger.info(f"User input - Invalid IP address type: {search_input}")
                    console.print(
                        f"[{colors['error']}]Invalid IP - multicast, broadcast, and reserved IPs are excluded.[/]\n"
                        f"[{colors['info']}]Enter a valid non-reserved IP[/]"
                    )
                    continue
                net_addresses.append(net)
                continue

    # One liner remove duplicates from net_addresses
    net_addresses = list(dict.fromkeys(net_addresses))

    if net_addresses and len(net_addresses) > 0:
        log_value = ", ".join([str(ip) for ip in net_addresses])
        logger.info(f"User input - {log_value}")
    else:
        return

    start = perf_counter()

    req_urls = {}
    processed_data = {}
    data_to_save = {}
    # Compile API request URIs to obtain general network information for each address
    for network in net_addresses:
        req_urls[network] = {
            "general": f"network?network={network}",
            "DNS records": f"ipv4address?network={network}&usage=DNS&_return_fields=ip_address,names",
            "network options": f"network?network={network}&_return_fields=options,members",
            "DHCP range": f"range?network={network}",
            "DHCP failover": f"range?network={network}&_return_fields=member,failover_association",
            "fixed addresses": f"fixedaddress?network={network}&_return_fields=ipv4addr,mac,name",
        }
        # process_data function will return 'DHCP members' and 'DHCP options' when type = 'network options'
        processed_data[network] = {
            "general": [],
            "DNS records": [],
            "DHCP options": [],
            "DHCP members": [],
            "DHCP range": [],
            "DHCP failover": [],
            "fixed addresses": [],
        }

    # Request general network information for each subnet
    for network in net_addresses:
        with ThreadPoolExecutor() as executor:
            with console.status(
                status=f"[{colors['description']}]Fetching [{colors['header']}]{network}[/] information...[/]"
            ):
                futures = {
                    label: executor.submit(
                        do_fancy_request,
                        logger=logger,
                        cfg=cfg,
                        message="",
                        endpoint=cfg["api_endpoint"],
                        uri=uri,
                        spinner=None,
                    )
                    for label, uri in req_urls[network].items()
                }
                results = {label: future.result() for label, future in futures.items()}

        for key, response in results.items():
            if response and len(response) > 0:
                processed_data[network].update(
                    process_data(logger, type=key, content=response)
                )

        # display data only if it is available
        data = []
        if len(processed_data[network]["general"]) > 0:
            # print_table_data(logger, processed_data[network], suffix={"general": "Information"})
            # Need to compile single 2d array with all the data to save it in xlsx
            dhcp_members_data = processed_data[network].get("DHCP members", "")
            dhcp_options_data = processed_data[network].get("DHCP options", "")
            dhcp_ranges_data = processed_data[network].get("DHCP range", "")
            dhcp_failover_data = processed_data[network].get("DHCP failover", "")
            dns_data = processed_data[network].get("DNS records", "")
            fixed_address_data = processed_data[network].get("fixed addresses", "")
            DHCP = "N"
            DHCP_Start = ""
            DHCP_End = ""
            DHCP_Servers = ""
            DHCP_Options = ""
            DHCP_Failover = ""
            notes = processed_data[network].get("general", [])[0].get("description", "")
            subnet = (
                processed_data[network].get("general", [])[0].get("subnet").split("/")
            )

            if len(dhcp_members_data) > 0 and len(dhcp_members_data[0]) > 0:
                DHCP = "Y"
                DHCP_Servers = "\n".join(
                    [
                        " - ".join([member["name"], member["IP Address"]])
                        for member in dhcp_members_data
                    ]
                )

            if len(dhcp_options_data) > 0 and len(dhcp_options_data[0]) > 0:
                DHCP_Options = "\n".join(
                    [
                        " - ".join([option["name"], option["value"]])
                        for option in dhcp_options_data
                    ]
                )
            # Only support single DHCP range with index 0
            if len(dhcp_ranges_data) > 0 and len(dhcp_ranges_data[0]) > 2:
                DHCP_Start = dhcp_ranges_data[0]["start address"]
                DHCP_End = dhcp_ranges_data[0]["end address"]
            if len(dhcp_failover_data) > 0 and len(dhcp_failover_data[0]) > 0:
                DHCP_Failover = dhcp_failover_data[0]["dhcp failover"]

            # Subnet row
            first_row = [
                subnet[0],
                f"/{subnet[1]}",
                "Subnet",
                "",
                DHCP,
                DHCP_Start,
                DHCP_End,
                DHCP_Servers,
                DHCP_Options,
                DHCP_Failover,
                notes,
            ]

            data.append(first_row)

            # Preparing DNS A records
            if len(dns_data) > 0:
                # Saving only all A records
                dns_rows = [
                    [
                        record["IP address"],
                        "/32",
                        record["A Record"],
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "DNS record",
                    ]
                    for record in dns_data
                ]
                data.extend(dns_rows)

            # Preparing Fixed IP records registerd in IPAM/DHCP
            if len(fixed_address_data) > 0:

                fixed_ip_rows = [
                    [
                        fixed_ip["IP address"],
                        "/32",
                        fixed_ip["name"],
                        fixed_ip["MAC"],
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "Fixed IP",
                    ]
                    for fixed_ip in fixed_address_data
                ]
                data.extend(fixed_ip_rows)

        data_to_save[network] = data

    end = perf_counter()

    logger.info(
        f"Request Type - Subnet Information - Search took {round(end-start, 3)} seconds!"
    )

    console.print("\n\n")
    console.print(
        f"[{colors['description']}]Request Type - Subnet Information - Search took [{colors['success']}]{round(end-start, 3)}[/] seconds![/]\n"
    )

    # Block will output just general subnet information with only subnet, subnet status and description fields
    missing_data_nets = 0
    if len(net_addresses) > 1:
        summary_data = {"summary data": []}
        for network in net_addresses:
            data = processed_data[network].get("general", [])
            summary_net = {}
            if len(data) > 0:
                summary_net["subnet"] = data[0].get("subnet")
                summary_net["description"] = data[0].get("description", "")
            else:
                missing_data_nets += 1
                summary_net["subnet"] = str(network)
                summary_net["description"] = "No data in Infoblox"

            summary_data["summary data"].append(summary_net)
        print_table_data(logger, cfg, summary_data)
        console.print(
            f"([{colors['success']}]Press [{colors['error']} {colors['bold']}]Q[/] to return to main menu(data will not be saved) / Any key - to get through detailed subnet data[/]\n"
        )
        key = read_single_keypress().lower()
        if key == "q":
            return

    # Block will print detailed subnet information one by one
    missing_data_nets = 0
    for network in net_addresses:
        if len(processed_data[network].get("general")) > 0:
            console.clear()
            print_table_data(
                logger, cfg, processed_data[network], suffix={"general": "Information"}
            )
            if missing_data_nets == net_addresses:
                return
            if len(net_addresses) - missing_data_nets > 1:
                console.print(
                    f"[{colors['success']}]Press [{colors['bold']}]SPACE[/] to see next result / Any key - return to the menu(request data will be saved in report file)[/]\n"
                )
                key = read_single_keypress()
                if key == " ":
                    continue
                else:
                    break
        else:
            missing_data_nets += 1
            if missing_data_nets == net_addresses:
                console.print(
                    f"[{colors['success']}]Network [{colors['error']} {colors['bold']}]{network}[/] has no data in Infoblox[/]\n"
                )
                return
            else:
                console.print(
                    f"[[{colors['success']}]]Network [{colors['error']} {colors['bold']}]{network}[/] has no data in Infoblox / Press [{colors['bold']}]SPACE[/] to see next result[/]\n"
                )

            key = read_single_keypress()
            if key == " ":
                continue
            else:
                break

    columns = [
        "IP",
        "Mask",
        "Name",
        "MAC",
        "DHCP",
        "DHCP Scope Start",
        "DHCP Scope End",
        "DHCP Servers",
        "DHCP Options\nOption - Value",
        "DHCP Failover Association",
        "Notes",
    ]
    columns_common = [
        "Search Network",
        "Status",
    ]
    data_combined = []
    common_search_results = []
    for network in net_addresses:
        if len(data_to_save[network]) > 0:
            common_search_results.append([network, "Used"])
            data_combined.extend(data_to_save[network])
        else:
            common_search_results.append([network, "No match"])

    # save data
    if cfg["auto_save"]:
        # Save general data
        queue_save(
            logger,
            cfg["report_filename"],
            columns_common,
            common_search_results,
            sheet_name="Subnet Data",
            force_header=True,
            index=False,
        )
        # Save main data
        if len(data_combined) > 0:
            queue_save(
                logger,
                cfg["report_filename"],
                columns,
                data_combined,
                sheet_name="Subnet Data",
                force_header=True,
                index=False,
            )
    return


def read_user_input(
    logger: logging.Logger, prompt: str = " ", read_pass: bool = False
) -> str:
    """
    Read user input and checks for CTRL-D/CTRL-C combinations
    If read_pass is True, function will request password string
    """
    raw_input = ""
    try:
        raw_input = console.input(
            f"{prompt}", password=read_pass, markup=True
        )
    except EOFError:
        pass
    except KeyboardInterrupt:
        interrupt_handler(logger, signal.SIGINT, None)

    return raw_input


def clear_report(logger: logging.Logger, cfg: dict) -> None:
    """
    Deletes the specified report file or the default report file (report.xlsx).

    @param logger: Logger instance.
    """
    colors = get_global_color_scheme(cfg)

    filename = cfg["report_filename"]
    if os.path.exists(filename):
        if logger:
            logger.info(f"Clear report - Deleting {filename}")

        os.remove(filename)
        console.print(f"[{colors['info']}]Report {filename} deleted[/]")
    else:
        console.print(f"[{colors['info']}]Report {filename} already deleted[/]")


def show_config_search_help(logger: logging.Logger, cfg: dict) -> None:

    colors = get_global_color_scheme(cfg)

    console.print(
        "\n"
        f"[{colors['warning']}]Unable to access configuration repository\n"
        f"Check [{colors['header']} {colors['bold']}][config_repository][/] section in the configuration file,\n"
        f"Verify that [{colors['success']} {colors['bold']}]storage_directory[/] parameter set to a proper path\n"
        f"If path is correct, verify that your account has read access to it[/]\n"
    )


def bulk_ping_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Runs multiple parallel ping processes against list of user supplied IP addresses
    """

    colors = get_global_color_scheme(cfg)

    logger.info("Request Type - Bulk PING")

    console.print(
        "\n"
        f"[{colors['description']}]Enter IPs/FQDNs to ping, one per line, non-valid IP/FQDNs are ignored.\n"
        "Empty input line starts ping process:[/]\n"
    )
    hosts = []
    raw_input = "none"
    while raw_input != "":
        raw_input = read_user_input(logger, "").strip()
        if not validate_ip(raw_input) and not is_fqdn(raw_input):
            continue
        hosts.append(raw_input)

    logger.info(f'User input - {", ".join(hosts)}')

    # One liner remove duplicates from hosts
    hosts = list(dict.fromkeys(hosts))

    if len(hosts) == 0:
        logger.info("No input data")
        return

    # Stackoverflow good example on how to run multiple pings at once
    # ip -> process
    p = {}
    results = {"Bulk PING": []}

    with console.status(f"[{colors['description']}]Pinging...[/]", spinner="dots12"):

        for host in hosts:
            # start ping processes - wait for 5 seconds to get 3 successful pings
            p[host] = Popen(
                ["ping", "-n", "-w5", "-c3", host], stdout=DEVNULL, stderr=STDOUT
            )

        while p:
            for host, proc in p.items():
                # ping finished
                if proc.poll() is not None:
                    # remove from the process list
                    del p[host]
                    if proc.returncode == 0:
                        results["Bulk PING"].append({"Host": f"{host}", "Result": "OK"})
                    elif proc.returncode == 1:
                        results["Bulk PING"].append(
                            {"Host": f"{host}", "Result": "NO RESPONSE"}
                        )
                    else:
                        results["Bulk PING"].append(
                            {"Host": f"{host}", "Result": "ERROR"}
                        )
                    break

    # Sort data per key
    sorted_results = {"Bulk PING": []}
    for host in hosts:
        for result in results["Bulk PING"]:
            if result["Host"] == host:
                sorted_results["Bulk PING"].append(result)

    print_table_data(logger, cfg, sorted_results)

    logger.debug(f"Request Type - Bulk PING - processed data {sorted_results}")

    if cfg["auto_save"] and len(sorted_results["Bulk PING"]) > 0:
        columns = ["Host", "Result"]
        save_data = []
        for ping_result in sorted_results["Bulk PING"]:
            save_data.append([ping_result["Host"], ping_result["Result"]])

        queue_save(
            logger,
            cfg["report_filename"],
            columns,
            save_data,
            sheet_name="Bulk PING",
            index=False,
            force_header=True,
        )
    return


def bulk_resolve_request(logger: logging.Logger, cfg: dict) -> None:
    """
    Resolves user supplied IP/FQDNs using system resolver using parallel threads
    """
    colors = get_global_color_scheme(cfg)

    logger.info("Request Type - Bulk PING")

    def resolve_ip(ip):
        try:
            result = socket.gethostbyaddr(ip)
        except (gaierror, herror, timeout):
            result = None

        return (ip, result)

    def resolve_name(name):
        try:
            result = socket.gethostbyname_ex(name)
        except (gaierror, herror, timeout):
            result = None

        return (name, result)

    logger.info("Request Type - Bulk DNS Lookup")

    console.print(
        "\n"
        f"[{colors['description']}]Enter FQDNs/IP addresses, one FQDN/IP address per line. Non-valid FQDNs/IPs are ignored.\n"
        "Empty input line starts lookup process:[/]\n"
    )

    data_lines = {"ip": [], "name": []}
    raw_input = "none"
    while raw_input != "":
        raw_input = read_user_input(logger, "").strip()
        if validate_ip(raw_input):
            data_lines["ip"].append(raw_input)
        elif is_fqdn(raw_input):
            data_lines["name"].append(raw_input)
        else:
            continue

    if len(data_lines["ip"]) == 0 and len(data_lines["name"]) == 0:
        logger.info("No input data")
        return

    logger.info(f"User input - {data_lines}")

    # Remove duplicates from data_lines
    data_lines["ip"] = list(dict.fromkeys(data_lines["ip"]))
    data_lines["name"] = list(dict.fromkeys(data_lines["name"]))

    results = {"Bulk Name Lookup": [], "Bulk IP Lookup": []}

    with console.status(f"[{colors['description']}]Resolving...[/]", spinner="dots12"):

        with ThreadPoolExecutor() as executor:
            ip_data = executor.map(resolve_ip, data_lines["ip"])
            name_data = executor.map(resolve_name, data_lines["name"])

    bulk_ip_results = []

    for req, data in ip_data:
        if data:
            # data[0] has primary result and data[1] is a list with the rest of the results
            bulk_ip_results.append({"IP": req, "Name": data[0]})
            for name in data[1]:
                bulk_ip_results.append({"IP": req, "Name": name})
        else:
            bulk_ip_results.append({"IP": req, "Name": "Not Resolved"})

    results["Bulk IP Lookup"].extend(bulk_ip_results)

    bulk_name_results = []

    for req, data in name_data:
        if data:
            # data[0] has proper fqdn if short hostname has been used
            # data[2] has a list of IPs resolved for the given fqdn
            if req != data[0]:
                name = f"{req}, {data[0]}"
            else:
                name = req
            for ip in data[2]:
                bulk_name_results.append({"Name": name, "IP": ip})
        else:
            bulk_name_results.append({"Name": req, "IP": "Not Resolved"})

    results["Bulk Name Lookup"].extend(bulk_name_results)

    # Sort data per original order (without duplicates)
    sorted_results = {"Bulk IP Lookup": [], "Bulk Name Lookup": []}
    for ip in data_lines["ip"]:
        for result in results["Bulk IP Lookup"]:
            if result["IP"] == ip:
                sorted_results["Bulk IP Lookup"].append(result)

    for name in data_lines["name"]:
        for result in results["Bulk IP Lookup"]:
            if result["Name"] == name:
                sorted_results["Bulk IP Lookup"].append(result)

    if len(results["Bulk IP Lookup"]) == 0 and len(results["Bulk Name Lookup"]) == 0:
        results["Bulk IP Lookup"].extend(
            list({"IP": ip, "Name": "Not Resolved"} for ip in data_lines["ip"])
        )
        results["Bulk Name Lookup"].extend(
            list({"Name": name, "IP": "Not Resolved"} for name in data_lines["name"])
        )
        print_table_data(logger, cfg, results)
        logger.debug("Request Type - Bulk DNS Lookup - unable to resolve any")
    else:
        print_table_data(logger, cfg, results)

    logger.debug(f"Request Type - Bulk DNS Lookup - processed data {results}")

    if cfg["auto_save"]:
        columns = ["Query", "Result"]
        save_data = []

        for name_result in results["Bulk Name Lookup"]:
            save_data.append([name_result["Name"], name_result["IP"]])

        for ip_result in results["Bulk IP Lookup"]:
            save_data.append([ip_result["IP"], ip_result["Name"]])

        queue_save(
            logger,
            cfg["report_filename"],
            columns,
            save_data,
            sheet_name="Bulk DNS Lookup",
            index=False,
            force_header=True,
        )
    return


def remove_duplicate_rows_sorted_by_col(data, col):
    """
    Removes duplicate rows from a list while preserving order
    and sorting the result by column number (col).

    Args:
        data: A list.

    Returns:
        A new list with duplicates removed and sorted by col.
    """
    seen = set()
    result = []
    for sublist in data:
        sublist_tuple = tuple(sublist)
        if sublist_tuple not in seen:
            seen.add(sublist_tuple)
            result.append(sublist)
    # Sort the result list based on col value
    result.sort(key=lambda sublist: sublist[col])
    return result


def extract_keywords(text):
    keywords = []
    # Remove non-alphanumeric chars
    text = re.sub(r"[\W_]+", " ", text)
    # Find both keywords and IP addresses in a single pass
    # r"(?:[a-zA-Z0-9]{10,13})\b|(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})|(?:\d{3,})|(?:[a-zA-Z]{3,})",
    for match in re.finditer(
        r"(?:[a-zA-Z0-9]{10,13})\b|(?:\d{3,})|(?:[a-zA-Z]{3,})",
        text,
    ):
        if match:  # Check if the match is not empty
            # discard to short keywords
            if len(match.group()) < 3:
                continue
            try:
                val = int(match.group())
            except ValueError:
                pass
            else:
                if val < 1000:
                    continue
            keywords.append(match.group().lower())
    return keywords


def get_facts_helper(logger: logging.Logger, cfg: dict, filename: str) -> tuple:
    """
    Function is a helper to run get_device_config in Multithreaded fashion
    """
    parts = filename.split("/")
    vendor = str(parts[4]).capitalize()
    device_type = str(parts[5]).upper()
    region = str(parts[6]).upper()
    # filename without .cfg - equals hostname
    hostname = parts[7][:-4].lower()

    logger.debug(f"Index Cache - Building {hostname.upper()} index data...")
    return get_device_facts(
        logger, cfg, hostname, region, vendor.lower(), device_type, filename
    )


def mt_index_configurations(logger, cfg):
    """Multithreaded version indexes configuration files and stores IP addresses and keywords in DiskCache
    at the moment there is an issue with the returned data and how it is being merged to dictionary, it is non-working properly function right now
    TODO: need to be fixed
    """
    filelist = []
    # by default do not index
    skip_indexing = True
    start = perf_counter()
    # Set indexing flag, other instances should avoid writing/indexing if flag is set
    cfg["dc"].set("indexing", True, expire=120)
    # Set updated to 0 to force fallback to old search method as cache might be inconsistent during indexing
    cfg["dc"].set("updated", 0)

    for folder in make_dir_list(logger, cfg):
        fn_list = os.listdir(folder)
        filelist.extend([f"{folder}/{f}" for f in fn_list if f.endswith(".cfg")])

    # Check create time for each file in list, if at least one is not matching - update skip_indexing to False
    for filename in filelist:
        hostname = filename.split("/")[7][:-4]
        updated_time = cfg["dev_idx"].get(hostname, {}).get("updated", 0)
        creation_time = os.path.getctime(filename)
        if creation_time - updated_time >= 0:
            skip_indexing = False

    if skip_indexing:
        logger.info("Index Cache - No configuration changes found...")
        cfg["dc"].pop("indexing", None)
        cfg["dc"].set("updated", time())
        return
    elif len(cfg["dev_idx"]) > 0:
        logger.info("Index Cache - Configuration repository updated. Clearing Index data...")
        cfg["ip_idx"].clear()
        logger.info("Index Cache - IP Index cleared...")
        cfg["kw_idx"].clear()
        logger.info("Index Cache - Keyword Index cleared...")
        cfg["dev_idx"].clear()
        logger.info("Index Cache - Device Index cleared...")
    else:
        pass

    if filelist:
        fn_len = len(filelist)
        processed_count = 0
        results = []

        # Limiting to 2 workers, but this can be changed depending on the system it runs on
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = (
                executor.submit(get_facts_helper, logger, cfg, filename)
                for filename in filelist
            )
            # results = {filename: future.result() for filename, future in futures.items()}
            for future in futures:
                results.append(future.result())
                if processed_count % 100 == 0:
                    cfg["dc"].touch("indexing", expire=120)
                    logger.info(
                        f"Index Cache - {round(processed_count / fn_len * 100, 2)}% completed..."
                    )
                processed_count += 1
        # merged_result = merge_dicts(*[item for item in results.values()])
        logger.info("Index Cache - 100% completed!")
        logger.info("Index Cache - Saving index data...")

        merged_devices = defaultdict(lambda: defaultdict)
        merged_ip_result = defaultdict(lambda: defaultdict(list))
        merged_kw_result = defaultdict(lambda: defaultdict(list))
        for _, ip_lst, _ in results:
            for key in ip_lst:
                ip, host = key
                merged_ip_result[ip][host] = sorted(set(merged_ip_result[ip][host] + list(ip_lst[key])))

        cfg["ip_idx"].update(merged_ip_result)
        logger.info("Index Cache - IP Index saved...")
        del merged_ip_result

        for _, _, kw_lst in results:
            for key in kw_lst:
                kw, host = key
                # print(ip, host, el[key])
                merged_kw_result[kw][host] = sorted(set(merged_kw_result[kw][host] + list(kw_lst[key])))
        cfg["kw_idx"].update(merged_kw_result)
        logger.info("Index Cache - Keyword Index saved...")
        del merged_kw_result

        for dev, _, _ in results:
            merged_devices.update(dev)
        cfg["dev_idx"].update(merged_devices)
        logger.info("Index Cache - Device Index saved...")
        del merged_devices

    end = perf_counter()

    # Set last update time in diskcache
    cfg["dc"].set("updated", time())

    # Set/Update cache version to current release
    if cfg["dc"].get("version", 0) != cache_version:
        cfg["dc"].set("version", cache_version)

    # Remove indexing flag
    cfg["dc"].pop("indexing", None)

    logger.info(f"Index Cache - Processing Time: {round(end-start, 3)} seconds")
    logger.info(
        f'Index Cache - Version: {cache_version} Devices: {len(cfg["dev_idx"])}, IP Addresses: {len(cfg["ip_idx"])}, Words:{len(cfg["kw_idx"])}'
    )


def get_device_facts(logger, cfg, hostname, region, vendor, device_type, fname) -> tuple:
    device = {
        "fname": fname,
        "region": region,
        "type": device_type,
        "vendor": vendor,
        "updated": time(),
    }

    ip_list = defaultdict(lambda: tuple([]))
    kw_list = defaultdict(lambda: tuple([]))

    def process_line(index, line):
        line = line.strip()
        if line.startswith(stop_words.get(vendor, ("NEVERMATCHED"))):
            return

        # Skip certificate data
        if re.match(r"^[0-9A-F]{8}\b", line) or re.match(r"^[0-9a-zA-Z/+]{65}$", line):
            return

        for match in re.finditer(ip_regexp, line):
            try:
                ip = ipaddress.ip_address(match.group())
                if not (ip.is_multicast or ip.is_reserved or ip.compressed.startswith(("255.", "0."))):
                    ip_list[(int(ipaddress.ip_address(ip)), hostname)] = ip_list[(int(ipaddress.ip_address(ip)), hostname)] + tuple([index])
            except ValueError:
                pass

        for word in set(extract_keywords(line)) - set(standard_keywords.get(vendor, ())):
            kw_list[(word, hostname)] = kw_list[(word, hostname)] + tuple([index])

    with open(fname, "r", encoding="utf-8") as f:
        for index, line in enumerate(f):
            process_line(index, line)

    return ({hostname: device}, ip_list, kw_list)


# @measure_execution_time
def search_cache_config(
    logger: logging.Logger,
    cfg: dict,
    folder: str,
    nets: list[ipaddress.IPv4Network],
    search_terms: list[re.Pattern],
    search_input: str,
) -> tuple[list, set]:

    data_to_save = []
    data, matched_nets = search_cache_subnets(logger, cfg, nets, search_input)
    data_to_save.extend(data)

    data = search_cache_keywords(logger, cfg, search_terms, search_input)
    data_to_save.extend(data)

    return data_to_save, matched_nets


# @measure_execution_time
def search_cache_keywords(
    logger: logging.Logger, cfg: dict, search_terms: list, search_input: str
) -> list:
    data_to_save = []
    kw_data = []
    for term in search_terms:
        words = extract_keywords(term)
        # logger.debug(f'Debug Words: {words}')
        for word in words:
            data = cfg["kw_idx"].get(word, None)
            if data:
                kw_data.append(data)
            else:
                # if no direct match to key in kw_idx, lets check if word is a partial match to the keys
                for word_key in cfg["kw_idx"].keys():
                    if word in word_key:
                        kw_data.append(cfg["kw_idx"].get(word_key, {}))

        for hostnames_data in list(kw_data):
            for hostname, data in hostnames_data.items():
                with open(cfg["dev_idx"].get(hostname, {}).get('fname', None), "r", encoding="utf-8") as f:
                    for index, line in yieldlines(f, data):
                        if re.search(term, line, re.IGNORECASE):
                            data_to_save.append([search_input, hostname, int(index), line.strip(), ''])
        kw_data.clear()

    return data_to_save


# @measure_execution_time
def search_cache_subnets(
    logger: logging.Logger, cfg: dict, nets: list, search_input: str
) -> tuple[list, set]:
    matched_nets = set()
    data_to_save = []
    rows_to_save = {}
    if nets is None or len(nets) == 0:
        return (data_to_save, matched_nets)

    # Create pool of all possible IP addresses in requested subnets
    network_ip_map = {}
    for net in nets:
        network_ip_map.setdefault(net, []).extend(ipaddress.ip_network(net).hosts())
        network_ip_map[net].extend([ipaddress.ip_network(net).network_address])

    # import ipdb; ipdb.set_trace()
    for subnet, ip_addresses in network_ip_map.items():
        for ip_address in ip_addresses:
            # if IP is in index, get device data dict where we can loop over devices and get configuration
            device_data = cfg["ip_idx"].get(int(ip_address), {})
            for found_device, device in device_data.items():
                # import ipdb; ipdb.set_trace()
                with open(cfg["dev_idx"].get(found_device, {}).get('fname', None), "r", encoding="utf-8") as f:
                    for index, line in yieldlines(f, device):
                        rows_to_save.setdefault(found_device, {})[index] = (
                            subnet.compressed,
                            ip_address.compressed,
                            line.strip(),
                        )

                matched_nets.add(subnet)

    # Saving all gathered data to data_to_save array
    if len(rows_to_save) > 0:
        for hostname, indices in sorted(rows_to_save.items()):
            for index, (subnet, _, line) in sorted(indices.items()):
                data_to_save.append(
                    [search_input, hostname.upper(), int(index), line, ""]
                )
            # For future update
            # for index, (subnet, ip, line) in sorted(indices.items()):
            #     data_to_save.append([subnet, hostname, ip, index, line])
    return (data_to_save, matched_nets)


def background_cache_init(logger, cfg):
    """Initialize cache in the background in a separate thread or refresh if cache already exists"""

    if not cfg["cache"]:
        # do nothing if cache is disabled
        return

    if cfg["dc"].get("indexing", None):
        # skip indexing if cache is already being indexed
        logger.info(
            "Index Cache - Another process performs indexing, skipping checks..."
        )
        return

    if time() - cfg["dc"].get("updated", 0) <= 300:
        logger.info("Index Cache - State is up-to-date, skipping checks...")
        return

    cache_ver = cfg["dc"].get("version", 0)
    if cache_ver == 0:
        logger.info("Index Cache - No cache found. Indexing data...")
    elif cache_ver != cache_version:
        # if updated key exists then cache has data and needs to be re-created due to version mismatch
        logger.info(
            f"Index Cache - Version: {cache_ver}. Required Version: {cache_version}. Indexing data..."
        )

    else:
        pass

    try:
        mt_index_configurations(logger, cfg)
    except Exception as e:
        logger.error(f"Index Cache - Error during cache initialization: {e}")


def check_file_accessibility(file_path: str, logger: logging.Logger) -> bool:
    """Check if the file exists and is readable."""
    if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
        logger.info(f"Unable to read {file_path}")
        return False
    return True


def check_dir_accessibility(dir_path: str, logger: logging.Logger) -> bool:
    """Check if the directory exists and is readable and accessible"""
    if len(dir_path) == 0:
        logger.info("Directory is not specified")
        return False
    if not os.path.isdir(dir_path) or not os.access(dir_path, os.R_OK):
        logger.info(f"Unable to access {dir_path}")
        return False
    return True


def check_file_timeliness(file_path: str, logger: logging.Logger) -> bool:
    """Check if the file's modification time is less than 24 hours ago."""
    modify_time = datetime.fromtimestamp(os.path.getmtime(file_path))
    if datetime.now() - modify_time > timedelta(hours=24):
        logger.info(f"File {file_path} is older than 24 hours")
        return False
    return True


def decrypt_gpg_file(file_path: str, logger: logging.Logger) -> str:
    """Attempt to decrypt the GPG file and handle possible subprocess exceptions."""
    try:
        result = subprocess.run(
            ["gpg", "--batch", "-d", file_path],
            capture_output=True,
            text=True,
            check=True,
            timeout=90,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Unable to decrypt {file_path} - {e}")
    except subprocess.TimeoutExpired:
        logger.error("GPG decryption took too long")
    return None


def parse_gpg_credentials(gpg_output: str) -> tuple:
    """Parse decrypted GPG output to extract user and password."""
    user = password = None
    for line in gpg_output.split("\n"):
        if line.startswith("User ="):
            user = line.split("=")[1].strip()
        elif line.startswith("Password ="):
            password = line.split("=")[1].strip()
    return (None, None) if not user or not password else (user, password)


def get_gpg_credentials(logger: logging.Logger, cfg: dict) -> any:
    """Main function to get decrypted GPG credentials."""
    file_path = cfg["gpg_credentials"]
    if not check_file_accessibility(file_path, logger) or not check_file_timeliness(
        file_path, logger
    ):
        return None

    decrypted_output = decrypt_gpg_file(file_path, logger)
    if decrypted_output is None:
        return None

    return parse_gpg_credentials(decrypted_output)


def get_auth_creds(logger: logging.Logger, cfg: dict) -> tuple:

    colors = get_global_color_scheme(cfg)

    # Read login credentials
    username = os.getenv("USER")
    password = os.getenv("TACACS_PW")

    # If TACACS_PW is not set, try GPG credential file
    creds = None
    if password is None or password == "":
        logger.info("Auth - TACACS_PW not set, checking GPG credentials")
        creds = get_gpg_credentials(logger, cfg)

        # If GPG credentials file does not exist or stale, request fresh credential from user
        if creds is None or (creds[0] is None or creds[1] is None):
            logger.info(
                "Auth - GPG credentials not available, requesting credential from user"
            )
            while password is None or password == "":
                console.clear()
                console.print(
                    "\n"
                    f"[{colors['description']}]Set up '[{colors['error']}]TACACS_PW[/]' environment variable to avoid typing in credential\n"
                    f"with each run or create/update [{colors['error']}]device-apply.gpg[/] credentials file\n"
                    f"For more infrmation run {os.path.basename(__file__)} with -h argument[/]\n"
                )
                password = read_user_input(
                    logger,
                    f"[{colors['header']} {colors['bold']}]Provide security credential:[/]",
                    True,
                )
        else:
            logger.info("Auth - GPG credentials obtained")
            username = creds[0]
            password = creds[1]

    return (username, password)


def get_global_color_scheme(cfg: dict) -> dict:
    color_scheme = cfg.get("theme", 'default')
    if color_scheme not in COLOR_SCHEMES:
        # print(f"Warning: Unknown color scheme '{color_scheme}'. Using default.")
        color_scheme = "default"

    return COLOR_SCHEMES[color_scheme]


def set_global_color_scheme(color_scheme):
    console.set_color_scheme(color_scheme)


def main() -> None:
    """
    Main function that orchestrates the execution of the script.
    """
    # default params if config is missing
    cfg = {
        "gpg_credentials": os.path.expanduser("~/device-apply.gpg"),
        "api_endpoint": "API_URL",
        "logfile_location": os.path.expanduser("~/cn.log"),
        "log_level_str": "INFO",
        "report_filename": os.path.expanduser("~/report.xlsx"),
        "auto_save": True,
        # Network devices confuration repository
        "store": "/opt/data/configs",
        "regions": ["ap", "eu", "am"],
        "vendors": ["cisco", "aruba", "paloalto", "f5", "bluecoat"],
        # Diskcache control
        "cache_directory": os.path.expanduser("~/.cn-cache"),
        "cache": True,
        # Other themes - monochrome, pastel, dark
        "theme": "default"
    }

    switch = {
        "1": ip_request,
        "2": subnet_request,
        "3": fqdn_request,
        "4": location_request,
        "5": search_config_request,
        "6": bulk_ping_request,
        "7": bulk_resolve_request,
        "8": demob_site_request,
        "9": device_query,
        "d": clear_report,
        "0": exit_now,
    }

    # Command-line argument parsing
    description = """
cn-tool v{version}

The tool allows to retrieve information from Infoblox and perform network operations.

Features:

- Performs IP/Subnet/DNS/Site information lookups using Infoblox API
- Performs bulk FQDN/IP ping operations
- Performs bulk FQDN/IP lookups using system resolver
- Performs search configuration storage (`/opt/data/configs/`) for obsolete data(cleanups on BGP borders/prefixes/ACLs)
- Obtains device information (sn, ios version and image, license data) in parallel
- Saves all requested information for later information processing(by default `report.xlsx` in $HOME directory)
- Keeps log of requests/responses(by default `cn.log` in $HOME directory)
- Can be easily configured by creating/changing configuration file(by default `.cn` in $HOME directory)

Useful tips:

Request for credential can be skipped if environmental variable `TACACS_PW` is set or device-apply.gpg file with credentials present in user directory.

- for environmental variable set up - copy lines below(including EOF) and paste in the terminal window:

cat >> ~/.bash_profile <<EOF
echo -n "Enter current TACACS_PW:"
read -s TACACS_PW
export TACACS_PW
EOF

It will update .bash_profile with the request to read `TACACS_PW` credential during login time. Re-login to the terminal to see it in action.

- for device-apply.gpg file creation use commands below, if file is older than 24 hours it won't be used:

device-apply --make-key
device-apply --make-credentials --overwrite

Create an alias for convenience by adding line to `.bash_profile`:

cat >> ~/.bash_profile <<EOF
alias cn="{exec_file}"
EOF

Re-login and start using cn-tool by running:
cn

Please send any feedback/feature requests to evdanil@gmail.com
""".format(
        version=version, exec_file=os.path.basename(__file__)
    )

    version_message = """
cn-tool v{version}

Please send any feedback/feature requests to evdanil@gmail.com
""".format(
        version=version
    )

    home_dir = os.getenv("HOME")

    parser = argparse.ArgumentParser(
        description=description, formatter_class=RawTextHelpFormatter
    )

    parser.add_argument(
        "-c",
        "--config",
        default=os.path.join(home_dir, ".cn"),
        help="specify configuration file(default $HOME/.cn)",
    )
    parser.add_argument(
        "-l", "--log-file", help="specify logfile(default $HOME/cn.log)"
    )
    parser.add_argument(
        "-nc", "--no-cache", action="store_true", help="run without cache use"
    )
    parser.add_argument(
        "-r", "--report-file", help="report filename(default $HOME/report.xlsx)"
    )
    parser.add_argument("-g", "--gpg-file", help="GPG credentials file")
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=version_message,
        help="show version number and exit",
    )

    args = parser.parse_args()

    # Read configuration
    cfg = read_config(cfg, os.path.expanduser(args.config))

    # Set color theme
    set_global_color_scheme(cfg["theme"])
    # set_global_color_scheme("pastel")

    # Overwrite config values with values from args
    if args.report_file and args.report_file != cfg["report_filename"]:
        cfg["report_filename"] = os.path.expanduser(args.report_file)

    if args.log_file and args.log_file != cfg["logfile_location"]:
        cfg["logfile_location"] = os.path.expanduser(args.log_file)

    if args.gpg_file and args.gpg_file != cfg["gpg_credentials"]:
        cfg["gpg_credentials"] = os.path.expanduser(args.gpg_file)

    if args.no_cache:
        cfg["cache"] = False

    # Configure logging
    cfg["log_level"] = logging.getLevelName(cfg["log_level_str"].upper())
    logger = configure_logging(cfg["logfile_location"], cfg["log_level"])

    # TODO add support for xls output format in parallel to console
    logger.info(
        f'cn-tool v{version} - api_endpoint: {cfg["api_endpoint"]} config_file: {args.config}'
    )

    # Auth tuple
    session.auth = get_auth_creds(logger, cfg)

    report_dir = os.path.split(cfg["report_filename"])[0]

    if len(report_dir) > 0 and not check_dir_accessibility(report_dir, logger):
        logger.info(
            f"Application - Reporting: Unable to access {report_dir} - Using current directory {os.getcwd()}"
        )
        cfg["report_filename"] = os.path.split(cfg["report_filename"])[1]
    elif len(report_dir) > 0:
        logger.info(f"Application - Reporting: Using directory {report_dir}")
    else:
        logger.info(f"Application - Reporting: Using directory {os.getcwd()}")

    directory = cfg["store"]
    if not check_dir_accessibility(directory, logger):
        logger.info(
            f"Application - Configuration Repository: Unable to access {directory} - configuration check disabled"
        )
        console.print(f"Unable to access {directory} - configuration check disabled")
        switch["5"] = show_config_search_help

    choice = "-1"

    # Setting CTRL-C intercept
    signal.signal(
        signal.SIGINT, lambda signum, frame: interrupt_handler(logger, signum, frame)
    )

    if cfg["api_endpoint"] == "API_URL":
        logger.error("API Error - Infoblox API endpoint URL is not set")
        exit_now(logger, exit_code=1, message='Correct Infoblox API URL is required(update configuration)')

    # Define cache variables
    if cfg["cache"]:
        logger.info(f'Index Cache - Cache Directory {cfg["cache_directory"]}')
        cfg["dc"] = FanoutCache(
            directory=cfg["cache_directory"],
            shards=4,
            timeout=1,
            disk=JSONDisk,
            compress_level=6,
            sqlite_synchronous=0,
            sqlite_auto_vacuum=0,
        )
        cfg["dev_idx"] = cfg["dc"].index("d_idx")
        cfg["ip_idx"] = cfg["dc"].index("i_idx")
        cfg["kw_idx"] = cfg["dc"].index("w_idx")

        cache_ver = cfg["dc"].get("version", None)
        if cache_ver:
            logger.info(
                f'Index Cache - Version: {cache_ver} Devices: {len(cfg["dev_idx"])}, IP Addresses: {len(cfg["ip_idx"])}, Words:{len(cfg["kw_idx"])}'
            )

        thread = threading.Thread(target=background_cache_init, args=(logger, cfg))
        thread.daemon = (
            True  # Allow the main program to exit even if the thread is still running
        )
        thread.start()

    # Start thread responsible for saving report files
    start_worker()

    colors = get_global_color_scheme(cfg)

    menu = f"""
    [{colors['error']} {colors['bold']}]MENU[/]
    [{colors['cyan']}]
    1. IP Information
    2. Subnet Information
    3. FQDN Prefix Lookup
    4. Subnet Lookup (by site code or keyword)
    5. Configuration Lookup (by subnet address or keyword)
    6. Bulk PING
    7. Bulk DNS Lookup
    8. Site Demobilization Check
    9. Device Information Request (Serial Number/IOS/License - only Cisco R&S)
    d. Delete Report[/]
    [{colors['warning']} {colors['bold']}]
    0. Exit
    [/]
    """

    while choice != "0":
        console.clear()
        console.print(menu)

        choice = read_user_input(logger, "Enter your choice: ")

        switch.get(choice, exit_now)(logger, cfg)

        console.print(f"[{colors['description']}]Press [{colors['error']}]Enter[/] key to continue[/]")
        read_user_input(logger, "")


if __name__ == "__main__":
    main()
