import ipaddress
import re
from collections.abc import Iterable

from utils.validation import is_fqdn, is_valid_site

from cn_lens.models import InvalidLensObject, LensObject, LensObjectType, ObjectSet


DEVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,62}$")
IPV4_LIKE_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def classify_one(raw: str) -> LensObject | InvalidLensObject:
    original = raw
    value = raw.strip()

    if not value:
        return InvalidLensObject(original=original, reason="empty input")

    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            pass
        else:
            if network.version == 4:
                normalized = str(network)
                return LensObject(
                    original=original,
                    normalized=normalized,
                    object_type=LensObjectType.PREFIX,
                    value=normalized,
                )
    else:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            if _is_ipv4_like(value):
                return InvalidLensObject(
                    original=original,
                    reason="unsupported object syntax",
                )
        else:
            if address.version == 4:
                normalized = str(address)
                return LensObject(
                    original=original,
                    normalized=normalized,
                    object_type=LensObjectType.IP,
                    value=normalized,
                )

    if is_valid_site(value):
        return LensObject(
            original=original,
            normalized=value,
            object_type=LensObjectType.SITE,
            value=value,
        )

    if "." in value and is_fqdn(value):
        return LensObject(
            original=original,
            normalized=value,
            object_type=LensObjectType.FQDN,
            value=value,
        )

    if " " not in value and DEVICE_RE.fullmatch(value):
        return LensObject(
            original=original,
            normalized=value,
            object_type=LensObjectType.DEVICE,
            value=value,
        )

    return InvalidLensObject(original=original, reason="unsupported object syntax")


def _is_ipv4_like(value: str) -> bool:
    return bool(IPV4_LIKE_RE.fullmatch(value))


def classify_many(raw_items: Iterable[str]) -> ObjectSet:
    objects: list[LensObject] = []
    invalid: list[InvalidLensObject] = []
    seen: set[tuple[LensObjectType, str]] = set()
    duplicate_count = 0

    for raw in raw_items:
        result = classify_one(raw)
        if isinstance(result, InvalidLensObject):
            invalid.append(result)
            continue

        key = (result.object_type, result.normalized)
        if key in seen:
            duplicate_count += 1
            continue

        seen.add(key)
        objects.append(result)

    return ObjectSet(
        objects=tuple(objects),
        invalid=tuple(invalid),
        duplicate_count=duplicate_count,
    )
