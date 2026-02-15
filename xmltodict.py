"""Minimal xmltodict-compatible parser for offline environments."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any


def _merge(target: dict[str, Any], key: str, value: Any) -> None:
    if key in target:
        existing = target[key]
        if isinstance(existing, list):
            existing.append(value)
        else:
            target[key] = [existing, value]
    else:
        target[key] = value


def _convert(elem: ET.Element) -> dict[str, Any]:
    node: dict[str, Any] = {}

    for attr_key, attr_value in elem.attrib.items():
        node[f"@{attr_key}"] = attr_value

    children = list(elem)
    for child in children:
        _merge(node, child.tag, _convert(child))

    text = (elem.text or "").strip()
    if text and not children:
        if node:
            node["#text"] = text
        else:
            return text

    return node


def parse(xml_input: str) -> dict[str, Any]:
    root = ET.fromstring(xml_input)
    return {root.tag: _convert(root)}
