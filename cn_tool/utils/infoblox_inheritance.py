from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Tuple


InheritanceMeta = Dict[str, Any]


def _blank_meta() -> InheritanceMeta:
    return {
        "inherited": False,
        "multisource": False,
        "source": "",
    }


def _is_inheritance_wrapper(value: Any) -> bool:
    return isinstance(value, Mapping) and "inherited" in value and ("value" in value or "values" in value)


def _extract_meta(wrapper: Mapping[str, Any]) -> InheritanceMeta:
    source = str(wrapper.get("source") or wrapper.get("inheritance_source") or "")
    return {
        "inherited": bool(wrapper.get("inherited", False)) or bool(source),
        "multisource": bool(wrapper.get("multisource", False)),
        "source": source,
    }


def _combine_meta(primary: InheritanceMeta, secondary: InheritanceMeta) -> InheritanceMeta:
    source = primary.get("source") or secondary.get("source") or ""
    multisource = bool(primary.get("multisource") or secondary.get("multisource"))
    if primary.get("source") and secondary.get("source") and primary.get("source") != secondary.get("source"):
        multisource = True
    return {
        "inherited": bool(primary.get("inherited") or secondary.get("inherited")),
        "multisource": multisource,
        "source": str(source),
    }


def unwrap_scalar_value(value: Any) -> Tuple[Any, InheritanceMeta]:
    """Unwrap one scalar inheritance wrapper into an effective value plus metadata."""
    if not _is_inheritance_wrapper(value):
        return value, _blank_meta()

    wrapper = dict(value)
    wrapper_meta = _extract_meta(wrapper)
    payload = wrapper.get("value", wrapper.get("values"))
    if isinstance(payload, list):
        for item in payload:
            if _is_inheritance_wrapper(item):
                item_meta = _combine_meta(wrapper_meta, _extract_meta(item))
                item_payload = item.get("value", item.get("values"))
                if item_payload not in (None, "", []):
                    return item_payload, item_meta
                continue
            if isinstance(item, Mapping) and "value" in item:
                return item.get("value"), wrapper_meta
            if item not in (None, "", []):
                return item, wrapper_meta
        return "", wrapper_meta
    return payload, wrapper_meta


def normalize_extattrs(value: Any) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, InheritanceMeta]]:
    """Normalize Infoblox extensible attributes without dropping multi-source groups."""
    extattrs: Dict[str, Dict[str, Any]] = {}
    metadata: Dict[str, InheritanceMeta] = {}

    def merge_attr(name: str, raw_value: Any, inherited_meta: InheritanceMeta) -> None:
        attr_record: Dict[str, Any]
        attr_meta = dict(inherited_meta)

        if _is_inheritance_wrapper(raw_value):
            effective_value, wrapper_meta = unwrap_scalar_value(raw_value)
            attr_record = {"value": effective_value}
            attr_meta = _combine_meta(attr_meta, wrapper_meta)
        elif isinstance(raw_value, Mapping):
            attr_record = dict(raw_value)
            attr_meta = _combine_meta(attr_meta, _extract_meta(raw_value))
        else:
            attr_record = {"value": raw_value}

        existing = extattrs.get(name)
        if existing is None or (existing.get("value") in (None, "") and attr_record.get("value") not in (None, "")):
            extattrs[name] = attr_record
        elif existing != attr_record:
            attr_meta["multisource"] = True

        metadata[name] = _combine_meta(metadata.get(name, _blank_meta()), attr_meta)

    def append_payload(payload: Any, inherited_meta: InheritanceMeta) -> None:
        if isinstance(payload, list):
            for item in payload:
                if _is_inheritance_wrapper(item):
                    append_payload(item.get("value", item.get("values")), _combine_meta(inherited_meta, _extract_meta(item)))
                    continue
                if isinstance(item, Mapping) and ("value" in item or "values" in item) and ("source" in item or "inheritance_source" in item):
                    append_payload(item.get("value", item.get("values")), _combine_meta(inherited_meta, _extract_meta(item)))
                    continue
                if isinstance(item, Mapping):
                    for key, item_value in item.items():
                        merge_attr(str(key), item_value, inherited_meta)
            return

        if not isinstance(payload, Mapping):
            return

        if _is_inheritance_wrapper(payload):
            append_payload(payload.get("value", payload.get("values")), _combine_meta(inherited_meta, _extract_meta(payload)))
            return

        for key, item_value in payload.items():
            merge_attr(str(key), item_value, inherited_meta)

    append_payload(value, _blank_meta())
    filtered_meta = {
        name: meta for name, meta in metadata.items()
        if meta.get("inherited") or meta.get("multisource")
    }
    return extattrs, filtered_meta


def expand_list_struct_field(value: Any) -> Tuple[List[Dict[str, Any]], List[InheritanceMeta]]:
    """Flatten inheritance-aware list-of-struct fields such as network options."""
    rows: List[Dict[str, Any]] = []
    metadata: List[InheritanceMeta] = []

    def append_payload(payload: Any, meta: InheritanceMeta) -> None:
        if isinstance(payload, list):
            for item in payload:
                if _is_inheritance_wrapper(item):
                    append_payload(item.get("value", item.get("values")), _combine_meta(meta, _extract_meta(item)))
                    continue
                if isinstance(item, Mapping):
                    rows.append(dict(item))
                    metadata.append(_combine_meta(meta, _extract_meta(item)))
        elif isinstance(payload, Mapping):
            rows.append(dict(payload))
            metadata.append(_combine_meta(meta, _extract_meta(payload)))

    if _is_inheritance_wrapper(value):
        wrapper = dict(value)
        append_payload(wrapper.get("value", wrapper.get("values")), _extract_meta(wrapper))
        return rows, metadata

    if not isinstance(value, list):
        return rows, metadata

    for item in value:
        if _is_inheritance_wrapper(item):
            wrapper = dict(item)
            append_payload(wrapper.get("value", wrapper.get("values")), _extract_meta(wrapper))
            continue
        if isinstance(item, Mapping):
            rows.append(dict(item))
            metadata.append(_blank_meta())
    return rows, metadata


def normalize_record_fields(
    record: Mapping[str, Any],
    *,
    scalar_fields: Sequence[str] = (),
    extattrs_fields: Sequence[str] = (),
    list_struct_fields: Sequence[str] = (),
) -> Dict[str, Any]:
    """
    Normalize one Infoblox item by unwrapping supported inheritance wrappers and
    attaching parsed inheritance metadata under `_inheritance`.
    """
    normalized = dict(record)
    inheritance: Dict[str, Any] = {}

    for field in scalar_fields:
        if field not in normalized:
            continue
        effective_value, meta = unwrap_scalar_value(normalized[field])
        normalized[field] = effective_value
        if meta["inherited"] or meta["multisource"]:
            inheritance[field] = meta

    for field in extattrs_fields:
        if field not in normalized:
            continue
        extattrs, extattrs_meta = normalize_extattrs(normalized[field])
        normalized[field] = extattrs
        if extattrs_meta:
            inheritance[field] = extattrs_meta

    for field in list_struct_fields:
        if field not in normalized:
            continue
        items, meta_list = expand_list_struct_field(normalized[field])
        normalized[field] = items
        if any(meta["inherited"] or meta["multisource"] for meta in meta_list):
            inheritance[field] = meta_list

    if inheritance:
        normalized["_inheritance"] = inheritance
    return normalized
