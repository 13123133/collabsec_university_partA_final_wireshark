from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List, Optional, Tuple


# Matches Wireshark "Info" column patterns like:
#   59043 → 8000 [SYN]
#   8000 → 59043 [SYN, ACK]
_ARROW_RE = re.compile(r"(?P<src_port>\d+)\s*→\s*(?P<dst_port>\d+)")


def _get(d: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return str(d[k])
    return ""


def _norm_ip(s: str) -> str:
    # Strip IPv6-mapped IPv4 prefix like ::ffff:192.168.0.218
    s = (s or "").strip()
    if s.startswith("::ffff:"):
        s = s.split("::ffff:", 1)[1]
    return s


def parse_wireshark_csv(csv_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse a Wireshark CSV export.

    Supports common export formats:
    1) File > Export Packet Dissections > As CSV... (Packet summary line)
       Columns: No., Time, Source, Destination, Protocol, Length, Info
    2) CSV containing field-based columns (ip.src/ip.dst/tcp.srcport/...)

    Returns normalized rows with keys:
      time, src, dst, proto, info, src_port, dst_port
    """
    if not csv_bytes:
        return []

    text = csv_bytes.decode("utf-8", errors="ignore")
    # Handle TSV-ish exports: replace \t with , if it looks tab separated.
    if "\t" in text and "," not in text.splitlines()[0]:
        text = text.replace("\t", ",")

    f = io.StringIO(text)
    reader = csv.DictReader(f)
    if not reader.fieldnames:
        return []

    rows: List[Dict[str, Any]] = []
    for r in reader:
        src = _norm_ip(_get(r, "Source", "ip.src", "ipv6.src", "src"))
        dst = _norm_ip(_get(r, "Destination", "ip.dst", "ipv6.dst", "dst"))
        proto = _get(r, "Protocol", "_ws.col.Protocol", "protocol").strip()
        info = _get(r, "Info", "_ws.col.Info", "info").strip()
        time_s = _get(r, "Time", "frame.time", "frame.time_epoch", "time").strip()

        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        # Prefer explicit TCP/UDP port columns if available
        sp = _get(r, "tcp.srcport", "udp.srcport", "srcport")
        dp = _get(r, "tcp.dstport", "udp.dstport", "dstport")
        if sp.isdigit():
            src_port = int(sp)
        if dp.isdigit():
            dst_port = int(dp)

        # Fallback: parse ports from Info summary
        if (src_port is None or dst_port is None) and info:
            m = _ARROW_RE.search(info)
            if m:
                try:
                    if src_port is None:
                        src_port = int(m.group("src_port"))
                    if dst_port is None:
                        dst_port = int(m.group("dst_port"))
                except Exception:
                    pass

        if not src or not dst:
            # Some exports use "Source"/"Destination" as hostnames.
            # We keep them anyway but only if at least one looks like an IP.
            src = src or _get(r, "Source", "src")
            dst = dst or _get(r, "Destination", "dst")

        if not src and not dst and not proto and not info:
            continue

        rows.append(
            {
                "time": time_s,
                "src": src,
                "dst": dst,
                "proto": proto,
                "info": info,
                "src_port": src_port,
                "dst_port": dst_port,
            }
        )

    return rows


def analyze_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Lightweight heuristic analysis for port-sweep + HTTP probing."""
    if not rows:
        return {}

    # Identify the most "active" src (likely attacker) by count.
    src_counts: Dict[str, int] = {}
    dst_counts: Dict[str, int] = {}
    for r in rows:
        s = str(r.get("src", ""))
        d = str(r.get("dst", ""))
        if s:
            src_counts[s] = src_counts.get(s, 0) + 1
        if d:
            dst_counts[d] = dst_counts.get(d, 0) + 1

    attacker_ip = max(src_counts.items(), key=lambda x: x[1])[0]
    target_ip = max(dst_counts.items(), key=lambda x: x[1])[0]

    # Collect port activity for attacker -> target
    dst_ports = set()
    syn_attempts = 0
    http_reqs = 0
    http_paths = set()
    open_ports = set()

    for r in rows:
        s = str(r.get("src", ""))
        d = str(r.get("dst", ""))
        proto = str(r.get("proto", ""))
        info = str(r.get("info", ""))
        sp = r.get("src_port")
        dp = r.get("dst_port")

        # Ports targeted by attacker
        if s == attacker_ip and d == target_ip and isinstance(dp, int):
            dst_ports.add(dp)
            if "[SYN" in info:
                syn_attempts += 1

        # Infer open ports by SYN,ACK responses from target
        if s == target_ip and d == attacker_ip and "SYN, ACK" in info and isinstance(sp, int):
            open_ports.add(int(sp))

        # HTTP requests
        if (proto.upper() == "HTTP") or ("HTTP" in info):
            if "GET " in info or "POST " in info or "HEAD " in info:
                http_reqs += 1
                # crude path extraction
                parts = info.split()
                if len(parts) >= 2 and parts[0] in {"GET", "POST", "HEAD"}:
                    http_paths.add(parts[1])

    label = "normal"
    if len(dst_ports) >= 5 or syn_attempts >= 10:
        label = "port_sweep"
    if http_reqs >= 3:
        label = "http_probe" if label == "normal" else f"{label}+http_probe"

    times = [str(r.get("time", "")) for r in rows if r.get("time")]

    from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List, Optional, Tuple


# Matches Wireshark "Info" column patterns like:
#   59043 → 8000 [SYN]
#   8000 → 59043 [SYN, ACK]
_ARROW_RE = re.compile(r"(?P<src_port>\d+)\s*→\s*(?P<dst_port>\d+)")


def _get(d: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return str(d[k])
    return ""


def _norm_ip(s: str) -> str:
    # Strip IPv6-mapped IPv4 prefix like ::ffff:192.168.0.218
    s = (s or "").strip()
    if s.startswith("::ffff:"):
        s = s.split("::ffff:", 1)[1]
    return s


def parse_wireshark_csv(csv_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse a Wireshark CSV export.

    Supports common export formats:
    1) File > Export Packet Dissections > As CSV... (Packet summary line)
       Columns: No., Time, Source, Destination, Protocol, Length, Info
    2) CSV containing field-based columns (ip.src/ip.dst/tcp.srcport/...)

    Returns normalized rows with keys:
      time, src, dst, proto, info, src_port, dst_port
    """
    if not csv_bytes:
        return []

    text = csv_bytes.decode("utf-8", errors="ignore")
    # Handle TSV-ish exports: replace \t with , if it looks tab separated.
    if "\t" in text and "," not in text.splitlines()[0]:
        text = text.replace("\t", ",")

    f = io.StringIO(text)
    reader = csv.DictReader(f)
    if not reader.fieldnames:
        return []

    rows: List[Dict[str, Any]] = []
    for r in reader:
        src = _norm_ip(_get(r, "Source", "ip.src", "ipv6.src", "src"))
        dst = _norm_ip(_get(r, "Destination", "ip.dst", "ipv6.dst", "dst"))
        proto = _get(r, "Protocol", "_ws.col.Protocol", "protocol").strip()
        info = _get(r, "Info", "_ws.col.Info", "info").strip()
        time_s = _get(r, "Time", "frame.time", "frame.time_epoch", "time").strip()

        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        # Prefer explicit TCP/UDP port columns if available
        sp = _get(r, "tcp.srcport", "udp.srcport", "srcport")
        dp = _get(r, "tcp.dstport", "udp.dstport", "dstport")
        if sp.isdigit():
            src_port = int(sp)
        if dp.isdigit():
            dst_port = int(dp)

        # Fallback: parse ports from Info summary
        if (src_port is None or dst_port is None) and info:
            m = _ARROW_RE.search(info)
            if m:
                try:
                    if src_port is None:
                        src_port = int(m.group("src_port"))
                    if dst_port is None:
                        dst_port = int(m.group("dst_port"))
                except Exception:
                    pass

        if not src or not dst:
            # Some exports use "Source"/"Destination" as hostnames.
            # We keep them anyway but only if at least one looks like an IP.
            src = src or _get(r, "Source", "src")
            dst = dst or _get(r, "Destination", "dst")

        if not src and not dst and not proto and not info:
            continue

        rows.append(
            {
                "time": time_s,
                "src": src,
                "dst": dst,
                "proto": proto,
                "info": info,
                "src_port": src_port,
                "dst_port": dst_port,
            }
        )

    return rows


def analyze_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Lightweight heuristic analysis for port-sweep + HTTP probing."""
    if not rows:
        return {}

    # Identify the most "active" src (likely attacker) by count.
    src_counts: Dict[str, int] = {}
    dst_counts: Dict[str, int] = {}
    for r in rows:
        s = str(r.get("src", ""))
        d = str(r.get("dst", ""))
        if s:
            src_counts[s] = src_counts.get(s, 0) + 1
        if d:
            dst_counts[d] = dst_counts.get(d, 0) + 1

    attacker_ip = max(src_counts.items(), key=lambda x: x[1])[0]
    target_ip = max(dst_counts.items(), key=lambda x: x[1])[0]

    # Collect port activity for attacker -> target
    dst_ports = set()
    syn_attempts = 0
    http_reqs = 0
    http_paths = set()
    open_ports = set()

    for r in rows:
        s = str(r.get("src", ""))
        d = str(r.get("dst", ""))
        proto = str(r.get("proto", ""))
        info = str(r.get("info", ""))
        sp = r.get("src_port")
        dp = r.get("dst_port")

        # Ports targeted by attacker
        if s == attacker_ip and d == target_ip and isinstance(dp, int):
            dst_ports.add(dp)
            if "[SYN" in info:
                syn_attempts += 1

        # Infer open ports by SYN,ACK responses from target
        if s == target_ip and d == attacker_ip and "SYN, ACK" in info and isinstance(sp, int):
            open_ports.add(int(sp))

        # HTTP requests
        if (proto.upper() == "HTTP") or ("HTTP" in info):
            if "GET " in info or "POST " in info or "HEAD " in info:
                http_reqs += 1
                # crude path extraction
                parts = info.split()
                if len(parts) >= 2 and parts[0] in {"GET", "POST", "HEAD"}:
                    http_paths.add(parts[1])

    label = "normal"
    if len(dst_ports) >= 5 or syn_attempts >= 10:
        label = "port_sweep"
    if http_reqs >= 3:
        label = "http_probe" if label == "normal" else f"{label}+http_probe"

    times = [str(r.get("time", "")) for r in rows if r.get("time")]

    return {
    
    "packets": len(rows),
    "top_attacker_ip": attacker_ip,
    "top_target_ip": target_ip,
    "open_ports_inferred": sorted(open_ports),
    "dst_ports_top_flow": sorted(dst_ports)[:10],
    "unique_dst_ports_top_flow": len(dst_ports),
    "unique_src_ips": len(src_counts),
    "unique_dst_ips": len(dst_counts),
    "label": label,

   
    "attacker_ip": attacker_ip,
    "target_ip": target_ip,
    "unique_target_ports": sorted(dst_ports),
    "open_ports": sorted(open_ports),
    "syn_attempts": syn_attempts,
    "http_requests": http_reqs,
    "http_paths": sorted(http_paths),
    "total_packets": len(rows),
    "time_first": times[0] if times else "",
    "time_last": times[-1] if times else "",
}
