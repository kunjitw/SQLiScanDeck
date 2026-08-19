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


_VIRTUAL_HINTS = ("vmware", "virtualbox", "vbox", "hyper-v", "vethernet", "wsl", "loopback",
                  "bluetooth", "tap-", "tunnel", "tailscale", "zerotier", "docker", "npcap",
                  "vpn", "virtual")


def list_interfaces():
    """Every IPv4 interface as {name, ip, up, virtual}. Best-effort; [] on failure.
    Lets the user pick the right NIC when auto-detection (the default-route trick) grabs
    a VPN / virtual adapter instead of the real LAN one."""
    out = []
    try:
        import psutil
    except Exception:
        return out
    try:
        stats = psutil.net_if_stats()
    except Exception:
        stats = {}
    try:
        for name, addrs in psutil.net_if_addrs().items():
            st = stats.get(name)
            up = bool(st.isup) if st is not None else True
            low = name.lower()
            virtual = any(h in low for h in _VIRTUAL_HINTS)
            for a in addrs:
                if getattr(a, "family", None) == socket.AF_INET:
                    ip = a.address
                    if ip and not ip.startswith("127."):
                        out.append({"name": name, "ip": ip, "up": up, "virtual": virtual})
    except Exception:
        pass
    return out


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


def get_ip_info(want_public=True, public_timeout=2.5, preferred_ip=None):
    """
    Returns a dict that ALWAYS succeeds:
      {
        "local":  "<intranet IP to SHOW: user's pick, else auto>",
        "public": "<public IP or None>",
        "all":    [ ...every detected local IP... ],
        "interfaces": [ {name, ip, up, virtual}, ... ],  # for the NIC picker
        "auto":   "<the default-route auto pick>",
        "preferred": "<the user's chosen IP or None>",
        "display":"<best single string to show, never blank>",
        "public_checked": bool,
      }
    """
    info = {
        "local": None,
        "public": None,
        "all": [],
        "interfaces": [],
        "auto": None,
        "preferred": preferred_ip or None,
        "display": "未能偵測",  # "unable to detect"
        "public_checked": False,
    }

    try:
        ifaces = list_interfaces()
        info["interfaces"] = ifaces
        outbound = _local_outbound_ip()
        info["auto"] = outbound
        all_ips = [i["ip"] for i in ifaces]
        if not all_ips:   # psutil unavailable -> fall back to the old outbound + hostname trick
            for ip in ([outbound] if outbound else []) + _hostname_ips():
                if ip and ip not in all_ips:
                    all_ips.append(ip)
        info["all"] = all_ips
        # Which local IP to SHOW: the user's pick (if that NIC is still present) wins;
        # else the default-route auto pick; else the first up, non-virtual NIC; else first.
        if preferred_ip and preferred_ip in all_ips:
            info["local"] = preferred_ip
        elif outbound and (not all_ips or outbound in all_ips):
            info["local"] = outbound
        elif ifaces:
            up_phys = [i["ip"] for i in ifaces if i.get("up") and not i.get("virtual")]
            info["local"] = up_phys[0] if up_phys else ifaces[0]["ip"]
        elif all_ips:
            info["local"] = all_ips[0]
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
