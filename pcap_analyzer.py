from __future__ import annotations

from typing import Dict, List, Set

try:
    from scapy.all import rdpcap, IP, TCP, UDP  # type: ignore
    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False


def extract_indicators(pcap_path: str, max_packets: int = 3000) -> Dict[str, object]:
    """Extract basic indicators from a PCAP file (prototype-level)."""
    if not HAS_SCAPY:
        raise RuntimeError("Scapy not installed or unavailable.")

    pkts = rdpcap(pcap_path, count=max_packets)
    ips: Set[str] = set()
    proto = {"TCP": 0, "UDP": 0, "OTHER": 0}

    for p in pkts:
        if IP not in p:
            continue
        ips.add(p[IP].src)
        ips.add(p[IP].dst)

        if TCP in p:
            proto["TCP"] += 1
        elif UDP in p:
            proto["UDP"] += 1
        else:
            proto["OTHER"] += 1

    return {
        "packet_count": len(pkts),
        "unique_ips": sorted(ips),
        "protocol_counts": proto,
    }


def match_ip_iocs(extracted_ips: List[str], iocs: List[dict]) -> List[dict]:
    """Return IOC records where ioc_type == 'ip' and value appears in extracted_ips."""
    ip_iocs = [x for x in iocs if x.get("ioc_type") == "ip" and x.get("status", "active") == "active"]
    values = {x.get("value") for x in ip_iocs}

    hits: List[dict] = []
    for ip in extracted_ips:
        if ip in values:
            hits.extend([x for x in ip_iocs if x.get("value") == ip])
    return hits
