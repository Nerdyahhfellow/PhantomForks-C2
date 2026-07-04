"""
dynamic_analysis.py

Orchestrates a full emulator-driven dynamic analysis run:

    1. Boot an emulator
    2. Install the APK
    3. Start a network capture (network_capture.py)
    4. Spawn the app under Frida with runtime hooks live from instruction one
       (frida_agent.py) — falls back to a plain `adb` launch if Frida isn't
       available, so network capture still works without it
    5. Simulate user interaction for the run duration
    6. Stop the capture and feed the resulting .pcap through the SAME
       `network_analysis.analyze_pcap()` used for user-uploaded pcaps, so
       downstream correlation/scoring/dashboard code needs zero changes to
       support either path
    7. Fold Frida's runtime findings (SMS sends, crypto use, sensitive file
       writes, live confirmed connections) into a `behaviors` list attached
       to the network report, so `scoring.py` can factor them into the score

Fixes applied vs. the original draft:
    - Missing imports for AndroidEmulatorController / RuntimeNetworkCapture /
      FridaAgent (would NameError immediately)
    - `time.time() - start_time % 10 < 1` operator-precedence bug meant
      periodic logcat/screenshot capture almost never fired; replaced with
      explicit next-fire-time tracking
    - Frida attach no longer happens before the app is launched
    - Hand-rolled HTTP parsing removed in favor of the existing, already
      correlation/scoring-compatible `analyze_pcap()`
"""

import time
import threading
import json
from datetime import datetime, timezone
from pathlib import Path

from emulator_controller import AndroidEmulatorController
from network_capture import RuntimeNetworkCapture
from frida_agent import FridaAgent
from network_analysis import analyze_pcap


class DynamicAnalyzer:
    """Orchestrate dynamic analysis of an APK."""

    def __init__(self, apk_path, static_report, output_dir="dynamic_analysis_output"):
        self.apk_path = apk_path
        self.static_report = static_report
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)

        self.emulator = None
        self.network_capture = None
        self.frida_agent = None

        self._frida_events = []
        self.progress = "pending"

    def _on_frida_event(self, event):
        self._frida_events.append(event)

    def _derive_behaviors(self, network_report):
        """Turn raw Frida events (+ the parsed network report) into a
        structured, severity-tagged behavior list."""
        behaviors = []
        static_urls = self.static_report.get("iocs", {}).get("urls", [])
        static_hosts = set()
        for u in static_urls:
            try:
                from urllib.parse import urlparse
                h = urlparse(u).hostname
                if h:
                    static_hosts.add(h.lower())
            except Exception:
                pass

        crypto_count = 0
        live_confirmed = set()

        for ev in self._frida_events:
            msg = ev.get("message", "")
            if not isinstance(msg, str):
                continue

            if msg.startswith("HTTP Connection:") or msg.startswith("Socket connection:"):
                target = msg.split(": ", 1)[1] if ": " in msg else msg
                for h in static_hosts:
                    if h in target:
                        live_confirmed.add(target)

            elif msg.startswith("SMS Sent to:"):
                behaviors.append({
                    "type": "sms_sent",
                    "description": msg,
                    "severity": "critical",
                    "timestamp": ev["timestamp"],
                })

            elif msg == "Cipher operation":
                crypto_count += 1

        if crypto_count:
            behaviors.append({
                "type": "crypto_usage",
                "description": f"{crypto_count} Cipher operation(s) observed at runtime.",
                "severity": "medium",
                "timestamp": time.time(),
            })

        for target in live_confirmed:
            behaviors.append({
                "type": "frida_confirmed_connection",
                "description": f"Runtime hook observed a live connection to {target}, "
                                f"matching a hardcoded static URL — confirmed even if the "
                                f"traffic was HTTPS-encrypted and invisible to plain pcap parsing.",
                "severity": "high",
                "timestamp": time.time(),
            })

        return behaviors

    def run_analysis(self, duration=60):
        """Run the full dynamic analysis pipeline. Returns a dict with a
        `network` key shaped exactly like `network_analysis.analyze_pcap()`'s
        output (plus a `behaviors` list folded in), so it's a drop-in
        replacement wherever a pcap-derived network report is expected."""
        start_time_iso = datetime.now(timezone.utc).isoformat()
        package_name = self.static_report.get("package")
        screenshots = []
        error = None
        logcat_log = []
        pcap_path = str(self.output_dir / "runtime_capture.pcap")

        if not package_name:
            return {"error": "Package name not found in static report.", "start_time": start_time_iso}

        try:
            self.progress = "starting_emulator"
            self.emulator = AndroidEmulatorController()
            if not self.emulator.start_emulator():
                raise RuntimeError("Failed to start emulator (boot timed out).")

            self.progress = "installing_apk"
            if not self.emulator.install_apk(self.apk_path):
                raise RuntimeError("Failed to install APK on emulator.")

            self.progress = "capturing_network"
            self.network_capture = RuntimeNetworkCapture(interface="any", output_file=pcap_path)
            self.network_capture.start_capture()

            self.progress = "launching_app"
            self.frida_agent = FridaAgent(package_name)
            frida_active = self.frida_agent.start_monitoring(self._on_frida_event)
            if frida_active:
                print("Frida monitoring active - app spawned with hooks live.")
            else:
                # Fall back to a plain launch so network capture still works
                # even without runtime instrumentation.
                print("Frida unavailable - falling back to plain launch (no runtime hooks).")
                self.emulator.launch_app(package_name)

            time.sleep(5)  # let the app finish starting up

            self.progress = "simulating_interaction"
            interaction_thread = threading.Thread(
                target=self.emulator.simulate_user_interaction, args=(duration,), daemon=True
            )
            interaction_thread.start()

            run_start = time.time()
            next_screenshot_at = run_start + 15
            next_logcat_at = run_start + 10

            while time.time() - run_start < duration:
                now = time.time()
                if now >= next_logcat_at:
                    logcat_log.append({"timestamp": now, "log": self.emulator.get_logcat(lines=200)})
                    next_logcat_at += 10
                if now >= next_screenshot_at:
                    shot_path = self.output_dir / f"screenshot_{int(now)}.png"
                    self.emulator.capture_screen(str(shot_path))
                    screenshots.append(str(shot_path))
                    next_screenshot_at += 15
                time.sleep(1)

            interaction_thread.join(timeout=10)

            self.progress = "stopping_capture"
            if frida_active:
                self.frida_agent.stop_monitoring()

            saved_pcap = self.network_capture.stop_capture()

            self.progress = "analyzing_traffic"
            if saved_pcap:
                network_report = analyze_pcap(saved_pcap)
            else:
                network_report = {"request_count": 0, "destinations": [], "beacons": [], "timeline": [], "network_score": 0}

            network_report["behaviors"] = self._derive_behaviors(network_report)

            self.progress = "cleaning_up"
            self.emulator.uninstall_apk(package_name)

        except Exception as e:
            error = str(e)
            print(f"Dynamic analysis error: {error}")
            network_report = {"request_count": 0, "destinations": [], "beacons": [], "timeline": [], "network_score": 0, "behaviors": []}
        finally:
            if self.emulator:
                self.emulator.stop_emulator()

        result = {
            "start_time": start_time_iso,
            "end_time": datetime.now(timezone.utc).isoformat(),
            "package_name": package_name,
            "network": network_report,
            "screenshots": screenshots,
            "logcat_excerpt": logcat_log[-3:],
        }
        if error:
            result["error"] = error

        self.progress = "error" if error else "completed"

        try:
            with open(self.output_dir / "dynamic_analysis.json", "w") as f:
                json.dump(result, f, indent=2, default=str)
        except Exception:
            pass

        return result
