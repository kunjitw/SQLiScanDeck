"""
IP detection with layered fallbacks.

Requirement: the web page must always show the current IP, but on an intranet
(or fully offline) we may not be able to determine a public IP -- and that must
NEVER crash anything. Every layer here is wrapped so a failure just degrades to
the next option and finally to a friendly "unknown" string.
"""
import socket
import urllib.request


def _local_outbound_ip():
    """
    The classic trick: open a UDP socket toward a public address. No packet is
    actually sent (UDP connect just sets the default route), so this works
    offline too -- it tells us which local interface *would* be used.
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        try:
            if s is not None:
                s.close()
        except Exception:
            pass


def _hostname_ips():
    ips = []
    try:
        hostname = socket.gethostname()
        try:
            ips.append(socket.gethostbyname(hostname))
        except Exception:
            pass
        try:
            for info in socket.getaddrinfo(hostname, None):
                ip = info[4][0]
                if ip and ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
    except Exception:
        pass
    # drop loopback-only noise if we have anything better
    return [ip for ip in ips if ip and not ip.startswith("127.")]


def _public_ip(timeout):
    """Best-effort public IP. Any failure returns None -- never raises."""
    endpoints = (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    )
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "ignore").strip()
                if text and len(text) <= 45:  # sanity: fits an IPv6 literal
                    return text
        except Exception:
            continue
    return None


def get_ip_info(want_public=True, public_timeout=2.5):
    """
    Returns a dict that ALWAYS succeeds:
      {
        "local":  "<intranet/outbound IP or None>",
        "public": "<public IP or None>",
        "all":    [ ...every detected local IP... ],
        "display":"<best single string to show, never blank>",
        "public_checked": bool,
      }
    """
    info = {
        "local": None,
        "public": None,
        "all": [],
        "display": "未能偵測",  # "unable to detect"
        "public_checked": False,
    }

    try:
        local = _local_outbound_ip()
        alt = _hostname_ips()
        all_ips = []
        for ip in ([local] if local else []) + alt:
            if ip and ip not in all_ips:
                all_ips.append(ip)
        info["all"] = all_ips
        info["local"] = local or (all_ips[0] if all_ips else None)
    except Exception:
        pass

    if want_public:
        info["public_checked"] = True
        try:
            info["public"] = _public_ip(public_timeout)
        except Exception:
            info["public"] = None

    # Build a display string that is never blank.
    if info["public"]:
        if info["local"] and info["local"] != info["public"]:
            info["display"] = "{} (內網 {})".format(info["public"], info["local"])
        else:
            info["display"] = info["public"]
    elif info["local"]:
        info["display"] = info["local"]
    elif info["all"]:
        info["display"] = info["all"][0]
    # else keeps the default "unable to detect"

    return info
