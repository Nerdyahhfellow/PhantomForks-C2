"""
network_capture.py

Captures raw network traffic during an emulator run using scapy's `sniff()`,
then writes it to a .pcap file. Deliberately does NOT do its own HTTP
parsing/correlation — that's `network_analysis.analyze_pcap()`'s job, so the
emulator-driven pipeline and the "upload your own pcap" pipeline both feed
the exact same downstream code (correlation, scoring, dashboard).
"""

import threading
from scapy.all import sniff, wrpcap


class RuntimeNetworkCapture:
    """Capture network traffic during app execution and save it as a .pcap
    for `network_analysis.analyze_pcap()` to parse afterward."""

    def __init__(self, interface="any", output_file="capture.pcap"):
        self.interface = interface
        self.output_file = output_file
        self.packets = []
        self.capturing = False
        self.capture_thread = None
        self._error = None

    def start_capture(self):
        self.capturing = True
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()

    def _capture_packets(self):
        def packet_handler(pkt):
            if self.capturing:
                self.packets.append(pkt)

        def stop_filter(pkt):
            return not self.capturing

        try:
            # "any" only works as a pseudo-interface on Linux; scapy raises on
            # other platforms, so fall back to the default interface there.
            sniff(iface=self.interface, prn=packet_handler, stop_filter=stop_filter, store=False)
        except Exception as e:
            try:
                sniff(prn=packet_handler, stop_filter=stop_filter, store=False)
            except Exception as e2:
                self._error = f"{e}; fallback also failed: {e2}"

    def stop_capture(self):
        """Stop capturing and write the pcap file. Returns the pcap path, or
        None if nothing was captured."""
        self.capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        if self.packets:
            wrpcap(self.output_file, self.packets)
            print(f"Saved {len(self.packets)} packets to {self.output_file}")
            return self.output_file
        return None
