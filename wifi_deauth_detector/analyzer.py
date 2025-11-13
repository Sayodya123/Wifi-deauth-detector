"""wifi_deauth_detector.analyzer

Offline analysis of pcap files to detect spikes of deauthentication / disassociation frames.
Requires scapy for reading pcap files.
"""

from scapy.all import rdpcap, Dot11, Dot11Deauth, Dot11Disas
from collections import defaultdict, deque
from datetime import datetime
import json
import os

DEFAULT_WINDOW_SECONDS = 10  # sliding window size to search for spikes
DEFAULT_THRESHOLD = 5       # number of deauth/disas frames in window considered suspicious

class DeauthEvent:
    def __init__(self, ts, src, bssid, reason=None, subtype=None):
        self.timestamp = ts
        self.src = src
        self.bssid = bssid
        self.reason = reason
        self.subtype = subtype

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "src": self.src,
            "bssid": self.bssid,
            "reason": self.reason,
            "subtype": self.subtype
        }

def _is_deauth_or_disas(pkt):
    # Packet must be 802.11 management subtype deauth or disassociation
    if not pkt.haslayer(Dot11):
        return False
    return pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas)

def parse_pcap(pcap_path):
    """
    Read a pcap and yield DeauthEvent objects for each deauth/disassoc frame.
    """
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(pcap_path)
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if _is_deauth_or_disas(pkt):
            ts = float(pkt.time)
            ts_iso = datetime.utcfromtimestamp(ts).isoformat() + "Z"
            dot11 = pkt.getlayer(Dot11)
            src = dot11.addr2
            bssid = dot11.addr3
            reason = None
            subtype = None
            if pkt.haslayer(Dot11Deauth):
                subtype = "deauth"
                try:
                    reason = pkt[Dot11Deauth].reason
                except Exception:
                    reason = None
            elif pkt.haslayer(Dot11Disas):
                subtype = "disassociation"
                try:
                    reason = pkt[Dot11Disas].reason
                except Exception:
                    reason = None
            yield DeauthEvent(ts_iso, src, bssid, reason, subtype)

def detect_spikes(pcap_path, window_seconds=DEFAULT_WINDOW_SECONDS, threshold=DEFAULT_THRESHOLD):
    """
    Analyze a pcap and return a list of detected suspicious windows.
    Each detection is a dict with bssid, start_time, end_time, count, top_sources.
    """
    events_by_bssid = defaultdict(list)
    for ev in parse_pcap(pcap_path):
        events_by_bssid[ev.bssid].append(ev)

    detections = []
    for bssid, events in events_by_bssid.items():
        # convert timestamps to datetime objects
        times = [datetime.fromisoformat(e.timestamp.replace("Z", "")) for e in events]
        q = deque()
        for idx, t in enumerate(times):
            q.append(idx)
            # pop from left while outside window
            while q and (t - times[q[0]]).total_seconds() > window_seconds:
                q.popleft()
            count = len(q)
            if count >= threshold:
                involved = events[q[0]:q[-1]+1]
                src_count = {}
                for ev in involved:
                    src_count[ev.src] = src_count.get(ev.src, 0) + 1
                top_sources = sorted(src_count.items(), key=lambda x: x[1], reverse=True)[:5]
                detection = {
                    "bssid": bssid,
                    "start_time": involved[0].timestamp,
                    "end_time": involved[-1].timestamp,
                    "count": count,
                    "top_sources": top_sources,
                    "events_sample": [e.to_dict() for e in involved[:10]]
                }
                detections.append(detection)
                q.clear()
    return detections

def generate_report(pcap_path, **kwargs):
    detections = detect_spikes(pcap_path, **kwargs)
    report = {
        "pcap": os.path.basename(pcap_path),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "detections": detections
    }
    return report

def save_report_json(report, out_path):
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
