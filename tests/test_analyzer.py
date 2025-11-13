import pytest
from wifi_deauth_detector.analyzer import detect_spikes

def test_detect_spikes_no_file():
    with pytest.raises(FileNotFoundError):
        detect_spikes("nonexistent.pcap")
