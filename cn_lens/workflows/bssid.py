"""bssid workflow — Aruba BSSID conversion from wired Ethernet MAC addresses.

Offline-always
--------------
This workflow performs pure arithmetic conversion only.  No live adapters
are ever consulted.  The result is deterministic for any given input, making
``--offline`` semantics the unconditional default.

Algorithm credit
----------------
Original algorithm: Kieran Morton (mortonese.com).  Ported from
``modules/aruba_bssids._wired_mac_to_bssids`` so that ``cn_lens`` stays
standalone and has zero imports from the ``modules/`` package.

Usage (CLI)
-----------
::

    cn-lens bssid d0:4d:c6:c8:6d:6e
    cn-lens bssid d0:4d:c6:c8:6d:6e --format json
    cn-lens bssid d0:4d:c6:c8:6d:6e aa:bb:cc:dd:ee:ff

Usage (REPL)
------------
::

    bssid d0:4d:c6:c8:6d:6e
    bssid d0:4d:c6:c8:6d:6e --format json

Input normalisation
-------------------
The following MAC address formats are accepted (case-insensitive):

* ``xx:xx:xx:xx:xx:xx``
* ``xx-xx-xx-xx-xx-xx``
* ``xxxx.xxxx.xxxx``
* ``xxxxxxxxxxxx``

All accepted formats are normalised to upper-case colon-separated form
(``XX:XX:XX:XX:XX:XX``) before conversion.  Invalid tokens are captured as
``InvalidLensObject`` entries in ``LensRun.inputs.invalid``; they do not
produce a ``LensResult`` and do not affect the exit code of valid results.

Output summary shape (per result)
----------------------------------
::

    {
        "wired_mac":  "D0:4D:C6:C8:6D:6E",
        "mac_24ghz":  "D0:4D:C6:06:D6:E0",
        "mac_5ghz":   "D0:4D:C6:06:D6:F0",
    }
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from cn_lens.models import (
    InvalidLensObject,
    LensFinding,
    LensObject,
    LensObjectType,
    LensResult,
    LensRun,
    ObjectSet,
)
from cn_lens.workflows._helpers import make_run_id


__all__ = [
    "_wired_mac_to_bssids",
    "_normalise_mac",
    "bssid_convert",
]


# ---------------------------------------------------------------------------
# Pure conversion  (ported from modules/aruba_bssids._wired_mac_to_bssids)
# ---------------------------------------------------------------------------

def _wired_mac_to_bssids(wired_mac: str, bssid: str) -> List[str]:
    """Convert a wired Ethernet MAC address to Aruba BSSID MACs.

    Parameters
    ----------
    wired_mac:
        Wired Ethernet MAC in upper-case colon-separated form
        (e.g. ``"D0:4D:C6:C8:6D:6E"``).
    bssid:
        BSSID offset as a decimal string (typically ``"16"``).

    Returns
    -------
    list[str]
        ``[mac_24ghz, mac_5ghz]`` — both in upper-case colon-separated form.

    Algorithm credit: Kieran Morton (mortonese.com).

    Examples
    --------
    >>> _wired_mac_to_bssids("D0:4D:C6:C8:6D:6E", "16")
    ['D0:4D:C6:06:D6:E0', 'D0:4D:C6:06:D6:F0']
    """
    clean_mac = wired_mac.replace(":", "")
    nic = clean_mac[6:16]
    nic = nic[1:16]
    binary_nic = format(int(nic, 16), "020b")
    binary_nic = binary_nic + "0000"
    a = binary_nic[0:4]
    b = "1000"
    y = int(a, 2) ^ int(b, 2)
    z = bin(y)[2:].zfill(len(a))
    binary_r0_nic = z + binary_nic[4:]
    binary_bssid = format(int(bssid, 10), "020b").zfill(len(binary_r0_nic))
    binary_r1_nic = bin(int(binary_r0_nic, 2) + int(binary_bssid, 2))[2:]
    r0_nic = hex(int(binary_r0_nic, 2))[2:].zfill(6)
    r1_nic = hex(int(binary_r1_nic, 2))[2:].zfill(6)
    r0_mac = clean_mac[0:6] + r0_nic
    r1_mac = clean_mac[0:6] + r1_nic
    r0_mac = (':'.join(r0_mac[i:i + 2] for i in range(0, len(r0_mac), 2))).upper()
    r1_mac = (':'.join(r1_mac[i:i + 2] for i in range(0, len(r1_mac), 2))).upper()
    return [r0_mac, r1_mac]


# ---------------------------------------------------------------------------
# MAC address normalisation  (ported from utils/validation.validate_and_normalize_mac_address)
# ---------------------------------------------------------------------------

_MAC_PATTERNS = [
    # xx:xx:xx:xx:xx:xx  or  xx-xx-xx-xx-xx-xx
    re.compile(
        r'^([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})'
        r'[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})$',
        re.IGNORECASE,
    ),
    # xxxx.xxxx.xxxx
    re.compile(r'^([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})$', re.IGNORECASE),
    # xxxxxxxxxxxx
    re.compile(r'^([0-9a-f]{12})$', re.IGNORECASE),
]


def _normalise_mac(raw: str) -> Optional[str]:
    """Parse *raw* as a MAC address and return upper-case colon-separated form.

    Returns ``None`` when *raw* does not match any supported format.

    Supported formats (case-insensitive):
    * ``xx:xx:xx:xx:xx:xx``
    * ``xx-xx-xx-xx-xx-xx``
    * ``xxxx.xxxx.xxxx``
    * ``xxxxxxxxxxxx``
    """
    stripped = raw.strip().lower()
    for pattern in _MAC_PATTERNS:
        m = pattern.match(stripped)
        if m is None:
            continue
        groups = m.groups()
        if len(groups) == 6:
            # Colon / dash format — groups are already 2-char octets
            return ':'.join(g.upper() for g in groups)
        elif len(groups) == 3:
            # Dot format — join 4-char groups into 12-char hex string
            flat = ''.join(groups)
            return ':'.join(flat[i:i + 2].upper() for i in range(0, 12, 2))
        else:
            # Plain 12-char hex
            return ':'.join(stripped[i:i + 2].upper() for i in range(0, 12, 2))
    return None


# ---------------------------------------------------------------------------
# Workflow entry point
# ---------------------------------------------------------------------------

_BSSID_OFFSET = "16"  # Standard Aruba 5GHz offset (matches donor module)

_CONVERTED_MESSAGE = "MAC address converted to Aruba BSSID radios"


def bssid_convert(
    targets: List[str],
    *,
    run_id: Optional[str] = None,
) -> LensRun:
    """Convert a list of wired MAC addresses to Aruba BSSID radio MACs.

    This workflow is **offline-always**: it performs pure arithmetic conversion
    and never contacts any live adapter.  The ``runtime`` parameter accepted by
    other workflows is intentionally absent here.

    Parameters
    ----------
    targets:
        Raw MAC address strings in any accepted format (see module docstring).
        Invalid entries are captured in ``LensRun.inputs.invalid``.
    run_id:
        Explicit run identifier.  When ``None``, a UTC timestamp is generated
        via :func:`~cn_lens.workflows._helpers.make_run_id`.

    Returns
    -------
    LensRun
        Always returned; never raises.
    """
    effective_run_id = run_id if run_id is not None else make_run_id()

    valid_objects: List[LensObject] = []
    invalid_objects: List[InvalidLensObject] = []
    seen: Dict[str, bool] = {}
    duplicate_count = 0

    for raw in targets:
        normalised = _normalise_mac(raw)
        if normalised is None:
            invalid_objects.append(
                InvalidLensObject(
                    original=raw,
                    reason="not a valid MAC address",
                )
            )
            continue
        if normalised in seen:
            duplicate_count += 1
            continue
        seen[normalised] = True
        valid_objects.append(
            LensObject(
                original=raw,
                normalized=normalised,
                object_type=LensObjectType.DEVICE,
                value=normalised,
            )
        )

    object_set = ObjectSet(
        objects=tuple(valid_objects),
        invalid=tuple(invalid_objects),
        duplicate_count=duplicate_count,
    )

    # Offline-always sources block: only the classifier is present.
    sources: Dict[str, str] = {"classifier": "ok"}

    results: List[LensResult] = []
    for obj in valid_objects:
        mac24, mac5 = _wired_mac_to_bssids(obj.value, _BSSID_OFFSET)
        summary: Dict[str, Any] = {
            "bssid": {
                "wired_mac": obj.value,
                "mac_24ghz": mac24,
                "mac_5ghz": mac5,
            },
        }
        finding = LensFinding(
            severity="info",
            source="classifier",
            message=_CONVERTED_MESSAGE,
            detail={"workflow": "bssid"},
        )
        results.append(
            LensResult(
                lens_object=obj,
                status="classified",
                summary=summary,
                findings=(finding,),
                sources=sources,
            )
        )

    return LensRun(
        schema_version=1,
        tool="cn-lens",
        workflow="bssid",
        run_id=effective_run_id,
        inputs=object_set,
        results=tuple(results),
        warnings=(),
        errors=(),
    )
