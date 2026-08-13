"""
Target signatures for dedup / history.

Goal: recognise when the "same" URL or API endpoint has been tested before,
even though volatile bits differ (ids in the path, changing values). We build
a stable signature from:

    METHOD + host + normalised-path + sorted(param names)

Values are intentionally ignored -- only the *shape* of the endpoint and the
set of parameter names matter for "did I test this already?".
"""
import re
import hashlib
from urllib.parse import urlsplit


# A path segment that looks like an id we should collapse to {id}.
_NUM = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")          # long hex blobs / hashes
_TOKEN = re.compile(r"^[A-Za-z0-9_-]+$")


def _looks_like_mixed_id(seg):
    """A long, digit-heavy opaque token (e.g. a hash or db id), NOT a readable
    slug that merely contains a digit. `download-report1` and `api-v2-endpoint`
    have an incidental digit (low ratio) and must stay distinct endpoints."""
    if len(seg) < 12 or not _TOKEN.match(seg):
        return False
    digits = sum(c.isdigit() for c in seg)
    return digits >= 4 and (digits / len(seg)) >= 0.30


def _normalise_segment(seg):
    if not seg:
        return seg
    if _NUM.match(seg) or _UUID.match(seg) or _HEX.match(seg) or _looks_like_mixed_id(seg):
        return "{id}"
    return seg.lower()


def normalise_path(path):
    if not path:
        return "/"
    parts = path.split("/")
    return "/".join(_normalise_segment(p) for p in parts) or "/"


def build_signature(method, url, param_names):
    """
    Return (signature_string, human_readable_endpoint).

    signature_string is a short stable hash used for exact history lookups.
    human_readable_endpoint is what we show the user, e.g. GET example.com/api/user/{id}
    """
    method = (method or "GET").upper()
    try:
        parts = urlsplit(url if "://" in (url or "") else "http://" + (url or ""))
        host = (parts.hostname or "").lower()
        if parts.port:
            host = "{}:{}".format(host, parts.port)
        npath = normalise_path(parts.path)
    except Exception:
        host = ""
        npath = "/"

    names = sorted({(n or "").strip() for n in (param_names or []) if n and n.strip()})
    endpoint = "{} {}{}".format(method, host, npath)
    raw = "{}\n{}".format(endpoint, ",".join(names))
    sig = hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:16]
    return sig, endpoint


def endpoint_signature(method, url):
    """
    A looser signature that ignores parameter names -- matches the same
    endpoint regardless of which params were present. Used to surface
    "you've touched this endpoint before" even if the param set differs.
    """
    sig, endpoint = build_signature(method, url, [])
    return sig, endpoint
