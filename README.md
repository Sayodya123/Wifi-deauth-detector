# wifi_deauth_detector

## Description
A safe, offline Python library that scans Wi‑Fi packet captures (pcap files) to detect suspicious deauthentication and disassociation spikes.  
Intended for education, incident response, and authorized network analysis. **Does not send or craft any wireless frames.**

## Features
- Parse pcap files and extract deauth/disassociation frames
- Detect time windows with unusually high counts
- Summarize top source MACs and sample events
- Output a JSON report for further analysis

## Installation

Clone the repository and install in editable mode:

```bash
git clone https://github.com/Sayodya123/Wifi-deauth-detector.git
cd Wifi-deauth-detector
pip install -e .
pip install scapy
```

This allows you to modify the library locally while still being able to import it in Python.

---

## Usage

```python
from wifi_deauth_detector import generate_report, save_report_json

report = generate_report("captures/my_capture.pcap", window_seconds=10, threshold=6)
save_report_json(report, "reports/my_capture_report.json")

print(f"Found {len(report['detections'])} suspicious windows")
for d in report["detections"]:
    print(d["bssid"], d["start_time"], d["count"])
```

---

## Legal & Ethical Disclaimer
Only analyze captures you are **authorized** to access. Generating or sending deauthentication frames against networks or devices you do not own or have explicit written permission for is **illegal in many jurisdictions**.  
Use this library responsibly and only in controlled or authorized environments.

---

## License
MIT — see `LICENSE` file.
