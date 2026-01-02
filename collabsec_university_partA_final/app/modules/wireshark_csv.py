# app/modules/wireshark_wire.py
from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List, Optional, Tuple


# Support both Wireshark arrow "→" and ASCII "->"
_ARROW_RE = re.compile(r"(?P<src_port>\d+)\s*(?:→|->)\s*(?P<dst_port>\d+)")


def _get(d: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return str(d[k])
    return ""


def _norm_ip(s: str) -> str:
    """Normalize IPs, remove IPv6-mapped prefix like ::ffff:192.168.0.218"""
    s = (s or "").strip()
    if s.startswith("::ffff:"):
        s = s.split("::ffff:", 1)[1]
    return s


def _looks_like_ip(s: str) -> bool:
    s = (s or "").strip()
    if not s:
        return False
    # very lightweight check
    if ":" in s:  # ipv6-ish
        return True
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def parse_wireshark_csv(csv_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse Wireshark CSV export.

    Works with:
    A) File > Export Packet Dissections > As CSV... (packet summary)
       Columns typically: No., Time, Source, Destination, Protocol, Length, Info
    B) tshark/field-based export with columns like ip.src/ip.dst/tcp.srcport...

    Returns rows with:
      time, src, dst, proto, info, src_port, dst_port
    """
    if not csv_bytes:
        return []

    text = csv_bytes.decode("utf-8", errors="ignore")

    # If it looks tab-separated, normalize to commas
    if "\t" in text and "," not in text.splitlines()[0]:
        text = text.replace("\t", ",")

    f = io.StringIO(text)
    reader = csv.DictReader(f)
    if not reader.fieldnames:
        return []

    rows: List[Dict[str, Any]] = []

    for r in reader:
        # Common names (Wireshark summary)
        src = _norm_ip(_get(r, "Source", "ip.src", "ipv6.src", "src"))
        dst = _norm_ip(_get(r, "Destination", "ip.dst", "ipv6.dst", "dst"))
        proto = _get(r, "Protocol", "_ws.col.Protocol", "protocol").strip()
        info = _get(r, "Info", "_ws.col.Info", "info").strip()
        time_s = _get(r, "Time", "frame.time_epoch", "frame.time", "_ws.col.Time", "time").strip()

        # Ports
        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        sp = _get(r, "tcp.srcport", "udp.srcport", "srcport", "src_port", "_ws.col.SrcPort")
        dp = _get(r, "tcp.dstport", "udp.dstport", "dstport", "dst_port", "_ws.col.DstPort")
        if sp.isdigit():
            src_port = int(sp)
        if dp.isdigit():
            dst_port = int(dp)

        # Fallback: parse from Info e.g. "59043 → 8000 [SYN]"
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

        # If source/destination are hostnames, keep them anyway
        if not src:
            src = _get(r, "Source", "src")
        if not dst:
            dst = _get(r, "Destination", "dst")

        # Ignore totally empty lines
        if not (src or dst or proto or info):
            continue

        rows.append(
            {
                "time": time_s,
                "src": src.strip(),
                "dst": dst.strip(),
                "proto": proto.strip(),
                "info": info.strip(),
                "src_port": src_port,
                "dst_port": dst_port,
            }
        )

    return rows


def filter_rows_by_ports(rows: List[Dict[str, Any]], focus_ports: Optional[List[int]]) -> List[Dict[str, Any]]:
    """Keep only rows where src_port or dst_port in focus_ports (if provided)."""
    if not focus_ports:
        return rows
    focus = set(focus_ports)
    out = []
    for r in rows:
        sp = r.get("src_port")
        dp = r.get("dst_port")
        if (isinstance(sp, int) and sp in focus) or (isinstance(dp, int) and dp in focus):
            out.append(r)
    return out if out else rows  # fallback to all if filter returns nothing


def guess_attacker_target(rows: List[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str], Dict[str, int], Dict[str, int]]:
    """Pick attacker/target by most frequent src/dst within the filtered rows."""
    src_counts: Dict[str, int] = {}
    dst_counts: Dict[str, int] = {}

    for r in rows:
        s = str(r.get("src", "")).strip()
        d = str(r.get("dst", "")).strip()
        if s:
            src_counts[s] = src_counts.get(s, 0) + 1
        if d:
            dst_counts[d] = dst_counts.get(d, 0) + 1

    if not src_counts or not dst_counts:
        return None, None, src_counts, dst_counts

    attacker = max(src_counts.items(), key=lambda x: x[1])[0]
    target = max(dst_counts.items(), key=lambda x: x[1])[0]
    return attacker, target, src_counts, dst_counts


def analyze_rows(rows: List[Dict[str, Any]], focus_ports: Optional[List[int]] = None) -> Dict[str, Any]:
    """Heuristic analysis: port sweep + HTTP probe indicators.

    Returns keys your Streamlit UI expects:
      packets, top_attacker_ip, top_target_ip, open_ports_inferred, scan_label,
      unique_src_ips, unique_dst_ips, dst_ports_top_flow
    """
    if not rows:
        return {
            "packets": 0,
            "top_attacker_ip": None,
            "top_target_ip": None,
            "open_ports_inferred": [],
            "scan_label": "normal",
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "dst_ports_top_flow": [],
            "unique_dst_ports_top_flow": 0,
            "syn_attempts": 0,
            "http_requests": 0,
            "http_paths": [],
        }

    rows2 = filter_rows_by_ports(rows, focus_ports)
    attacker_ip, target_ip, src_counts, dst_counts = guess_attacker_target(rows2)

    if not attacker_ip or not target_ip:
        return {
            "packets": len(rows2),
            "top_attacker_ip": attacker_ip,
            "top_target_ip": target_ip,
            "open_ports_inferred": [],
            "scan_label": "normal",
            "unique_src_ips": len(src_counts),
            "unique_dst_ips": len(dst_counts),
            "dst_ports_top_flow": [],
            "unique_dst_ports_top_flow": 0,
            "syn_attempts": 0,
            "http_requests": 0,
            "http_paths": [],
        }

    dst_ports = set()
    open_ports = set()
    syn_attempts = 0

    http_reqs = 0
    http_paths = set()

    for r in rows2:
        s = str(r.get("src", "")).strip()
        d = str(r.get("dst", "")).strip()
        proto = str(r.get("proto", "")).strip().upper()
        info = str(r.get("info", "")).strip()
        sp = r.get("src_port")
        dp = r.get("dst_port")

        # Attacker -> Target
        if s == attacker_ip and d == target_ip and isinstance(dp, int):
            dst_ports.add(dp)
            # Wireshark info like "[SYN]" or "SYN"
            if "SYN" in info and "ACK" not in info:
                syn_attempts += 1

        # Target -> Attacker: SYN,ACK suggests port open
        if s == target_ip and d == attacker_ip and "SYN" in info and "ACK" in info and isinstance(sp, int):
            open_ports.add(int(sp))

        # HTTP request detection
        if proto == "HTTP" or "HTTP" in info:
            if "GET " in info or "POST " in info or "HEAD " in info:
                http_reqs += 1
                parts = info.split()
                if len(parts) >= 2 and parts[0] in {"GET", "POST", "HEAD"}:
                    http_paths.add(parts[1])

    # Label rules
    scan_label = "normal"
    if len(dst_ports) >= 5 or syn_attempts >= 10:
        scan_label = "port_sweep"
    if http_reqs >= 3:
        scan_label = "http_probe" if scan_label == "normal" else f"{scan_label}+http_probe"

    return {
        # ✅ UI fields
        "packets": len(rows2),
        "top_attacker_ip": attacker_ip,
        "top_target_ip": target_ip,
        "open_ports_inferred": sorted(open_ports),
        "scan_label": scan_label,

        "unique_src_ips": len(src_counts),
        "unique_dst_ips": len(dst_counts),
        "dst_ports_top_flow": sorted(dst_ports)[:10],
        "unique_dst_ports_top_flow": len(dst_ports),

        # ✅ extra (good for report)
        "syn_attempts": syn_attempts,
        "http_requests": http_reqs,
        "http_paths": sorted(http_paths),
    }


def make_ioc_incident_audit(summary: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """Optional helper:
    Convert summary into simple IOC + Incident + Audit records
    (方便你直接写入 JSON / 显示在 UI).
    """
    attacker = summary.get("top_attacker_ip")
    target = summary.get("top_target_ip")
    open_ports = summary.get("open_ports_inferred") or []
    label = summary.get("scan_label", "normal")
    packets = summary.get("packets", 0)

    ioc = {
        "type": "ip",
        "value": attacker,
        "context": f"Top src observed targeting {target}",
        "confidence": "medium" if label != "normal" else "low",
        "tags": ["wireshark", "csv", label],
    }

    incident = {
        "title": f"Network activity detected: {label}",
        "severity": "Medium" if label != "normal" else "Low",
        "attacker_ip": attacker,
        "target_ip": target,
        "open_ports_inferred": open_ports,
        "packet_count": packets,
        "status": "Open" if label != "normal" else "Info",
        "description": f"Detected {label} behavior from {attacker} to {target}.",
    }

    audit = {
        "action": "PCAP/CSV Analysis",
        "result": label,
        "details": f"Packets={packets}, OpenPorts={open_ports}",
        "actor": "system",
    }

    return ioc, incident, audit

