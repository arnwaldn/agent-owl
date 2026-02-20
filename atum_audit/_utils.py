"""ATUM Audit — Shared utility functions."""

from __future__ import annotations

from rdflib import URIRef

__all__ = ["local_name"]


def local_name(uri: URIRef | str | None) -> str:
    """Extract the local name from a URI (after # or last /).

    Accepts rdflib URIRef, plain strings, or None.
    Returns the fragment after '#' if present, otherwise the last path segment.
    """
    if uri is None:
        return ""
    s = str(uri)
    if "#" in s:
        return s.rsplit("#", 1)[-1]
    return s.rsplit("/", 1)[-1]
