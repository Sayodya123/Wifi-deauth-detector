# Wifi-deauth-detector
A safe, offline tool that scans pcap files to detect suspicious Wi‑Fi deauthentication/disassociation spikes.

## Description
A safe, offline Python library that scans Wi‑Fi packet captures (pcap files) to detect suspicious deauthentication and disassociation spikes.  
Intended for education, incident response, and authorized network analysis. **Does not send or craft any wireless frames.**

## Features
- Parse pcap files and extract deauth/disassociation frames
- Detect time windows with unusually high counts
- Summarize top source MACs and sample events
- Output a JSON report for further analysis

## Installation
```bash
git clone <repo-url>
cd wifi_deauth_detector_pkg
pip install -e .
pip install scapy
