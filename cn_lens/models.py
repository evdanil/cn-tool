from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class LensObjectType(str, Enum):
    IP = "ip"
    PREFIX = "prefix"
    FQDN = "fqdn"
    SITE = "site"
    DEVICE = "device"
    REPORT = "report"
    QUERY = "query"  # config find raw query token (not classifier-classified)


@dataclass(frozen=True)
class LensObject:
    original: str
    normalized: str
    object_type: LensObjectType
    value: str
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class InvalidLensObject:
    original: str
    reason: str


@dataclass(frozen=True)
class ObjectSet:
    objects: tuple[LensObject, ...]
    invalid: tuple[InvalidLensObject, ...]
    duplicate_count: int


@dataclass(frozen=True)
class LensFinding:
    severity: str
    source: str
    message: str
    detail: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LensResult:
    lens_object: LensObject
    status: str
    summary: Mapping[str, Any]
    findings: tuple[LensFinding, ...] = ()
    sources: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class LensRun:
    schema_version: int
    tool: str
    workflow: str
    run_id: str
    inputs: ObjectSet
    results: tuple[LensResult, ...]
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
