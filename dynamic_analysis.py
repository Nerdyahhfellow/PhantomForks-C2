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
from frida_agent import FridaAgent, FRIDA_AVAILABLE
from network_analysis import analyze_pcap
from static_analysis import analyze_apk
from correlate import correlate
from verdict import build_verdict


def _derive_behaviors_and_signals(frida_events, static_report):
    """Turn raw Frida events (+ the sample's own static IOCs) into:
      - `behaviors`: a structured, severity-tagged list for the dashboard's
        "Runtime Behaviors" table (and, via scoring.py, the risk score)
      - `evasion_signals`: the subset specifically about detecting whether
        the app is probing for an emulated/sandboxed environment
      - `dropped_apk_paths`: on-device paths of any file the app wrote whose
        name ends in .apk — i.e. a candidate second-stage payload to pull
        and analyze in its own right

    Pulled out as a standalone function (rather than a DynamicAnalyzer
    method) so it can be reused as-is for the nested dynamic pass over a
    dropped APK, which has its own frida events and its own static report
    and has no reason to spin up a whole second DynamicAnalyzer/emulator.
    """
    behaviors = []
    evasion_signals = []
    dropped_apk_paths = set()

    static_urls = static_report.get("iocs", {}).get("urls", [])
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

    for ev in frida_events:
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

        elif msg.startswith("APK write:"):
            path = msg.split(": ", 1)[1]
            dropped_apk_paths.add(path)
            behaviors.append({
                "type": "dropped_apk_write",
                "description": f"App wrote a local file ending in .apk: {path} — "
                                f"consistent with a dropper fetching a second-stage payload.",
                "severity": "critical",
                "timestamp": ev["timestamp"],
            })

        elif msg.startswith("Download request:"):
            uri = msg.split(": ", 1)[1]
            if ".apk" in uri.lower():
                behaviors.append({
                    "type": "apk_download_request",
                    "description": f"App issued a download request for {uri} — "
                                    f"likely fetching a second-stage APK payload.",
                    "severity": "high",
                    "timestamp": ev["timestamp"],
                })

        elif msg == "Package installer commit":
            behaviors.append({
                "type": "silent_install_attempt",
                "description": "App committed a PackageInstaller session — used to install "
                                "another APK, potentially without showing the normal install prompt.",
                "severity": "critical",
                "timestamp": ev["timestamp"],
            })

        elif msg.startswith("System property check:"):
            key = msg.split(": ", 1)[1]
            entry = {
                "type": "emulator_detection",
                "description": f"Queried system property '{key}', a value commonly used "
                                f"to fingerprint emulators/sandboxes.",
                "severity": "high",
                "timestamp": ev["timestamp"],
            }
            behaviors.append(entry)
            evasion_signals.append(entry)

        elif msg.startswith("Emulator artifact check:"):
            path = msg.split(": ", 1)[1]
            entry = {
                "type": "emulator_detection",
                "description": f"Checked for the existence of a known emulator-only file: {path}",
                "severity": "high",
                "timestamp": ev["timestamp"],
            }
            behaviors.append(entry)
            evasion_signals.append(entry)

        elif msg.startswith("Device fingerprint check:"):
            api = msg.split(": ", 1)[1]
            entry = {
                "type": "device_fingerprinting",
                "description": f"Queried {api} — often paired with emulator-detection logic "
                                f"to confirm a real device/SIM is present.",
                "severity": "medium",
                "timestamp": ev["timestamp"],
            }
            behaviors.append(entry)
            evasion_signals.append(entry)

        elif msg.startswith("Shell command:"):
            cmd = msg.split(": ", 1)[1]
            kind = "emulator_detection" if "getprop" in cmd else "root_check"
            severity = "high" if kind == "emulator_detection" else "medium"
            entry = {
                "type": kind,
                "description": f"Ran shell command probing device/root state: {cmd}",
                "severity": severity,
                "timestamp": ev["timestamp"],
            }
            behaviors.append(entry)
            evasion_signals.append(entry)

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

    return behaviors, evasion_signals, dropped_apk_paths


def _merge_filesystem_dropped_apks(dropped_apk_paths, behaviors, fs_before, fs_after):
    """Union the hook-based `dropped_apk_paths` with anything new the
    before/after filesystem sweep turned up, and add a behavior entry for
    any path the sweep caught that the Frida hooks didn't (so it's visible
    in the Runtime Behaviors table why it was flagged).

    Returns the merged set of paths to chase down; mutates `behaviors` in
    place, same as `_derive_behaviors_and_signals` does for the hook-based
    findings.
    """
    fs_new = {p for p in (fs_after - fs_before) if p}
    hook_detected = set(dropped_apk_paths)
    fs_only = fs_new - hook_detected

    for path in fs_only:
        behaviors.append({
            "type": "dropped_apk_write",
            "description": f"Filesystem sweep found a new .apk file written during this run "
                            f"that runtime hooks didn't catch: {path} — likely written via an "
                            f"API not covered by the current Frida hooks (e.g. buffered/native "
                            f"writes, or a temp-name-then-rename pattern).",
            "severity": "critical",
            "timestamp": time.time(),
        })

    return hook_detected | fs_new


# Noise to exclude when diffing installed-package lists — packages that
# appear "new" between snapshots but aren't a second-stage payload: the
# sample's own package (already tracked separately) and stock AOSP/Play
# Services components that can lazily appear/update on a freshly-booted
# emulator independent of anything the sample under test did.
_SYSTEM_PACKAGE_PREFIXES = ("com.android.", "com.google.android.", "android")


def _merge_package_installs(emulator, dropped_apk_paths, behaviors, own_package, pkg_before, pkg_after):
    """Union `dropped_apk_paths` with any package that newly appears
    between an installed-package-list before/after snapshot, resolving
    each to its actual APK path via `pm path`.

    This is the root-free counterpart to `_merge_filesystem_dropped_apks`:
    it exists specifically to catch a dropper that silently installs its
    payload through a `PackageInstaller` session (write bytes into the
    session, then `commit()`) rather than writing a loose `.apk` file
    anywhere the filesystem sweep looks. On a non-rooted device that sweep
    can't see into `/data/app` at all, so without this check that install
    technique produces a `silent_install_attempt` behavior note but no
    dropped-APK entry to actually pull and analyze.
    """
    new_packages = {
        p for p in (pkg_after - pkg_before)
        if p and p != own_package and not p.startswith(_SYSTEM_PACKAGE_PREFIXES)
    }
    resolved = set(dropped_apk_paths)
    for pkg in new_packages:
        path = emulator.get_apk_path_for_package(pkg)
        if not path or path in resolved:
            continue
        resolved.add(path)
        behaviors.append({
            "type": "dropped_apk_write",
            "description": f"Package-list diff found a newly-installed package during this run "
                            f"that neither runtime hooks nor the filesystem sweep caught by "
                            f"filename: {pkg} (resolved to {path}) — consistent with a silent "
                            f"install via a PackageInstaller session rather than a loose .apk "
                            f"file write.",
            "severity": "critical",
            "timestamp": time.time(),
        })
    return resolved


def _summarize_evasion(evasion_signals):
    """Roll up individual evasion-related Frida events into one summary
    the dashboard can show at a glance."""
    if not evasion_signals:
        return {"attempted": False, "confidence": "none", "signals": []}
    strong = [s for s in evasion_signals if s.get("type") == "emulator_detection"]
    confidence = "high" if len(strong) >= 2 else ("medium" if strong else "low")
    return {"attempted": True, "confidence": confidence, "signals": evasion_signals}


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

    def _handle_dropped_apks(self, dropped_apk_paths, total_duration):
        """Pull any candidate second-stage APK(s) the sample wrote to disk,
        run static analysis on each (host-side, cheap), then a short nested
        dynamic pass on the same still-running emulator so we see what the
        dropped payload itself does — not just what the parent claims about
        it. Runs before the parent's own teardown/reset so the files are
        still on the device to pull."""
        results = []
        if not dropped_apk_paths:
            return results

        # Cap how many we chase down — a sample that drops many files
        # shouldn't turn one scan into an unbounded chain of sub-analyses.
        candidate_paths = list(dropped_apk_paths)[:3]
        dropped_dir = self.output_dir / "dropped_apks"
        dropped_dir.mkdir(exist_ok=True, parents=True)

        for idx, remote_path in enumerate(candidate_paths):
            local_path = dropped_dir / f"dropped_{idx}.apk"
            entry = {"source_path_on_device": remote_path}

            self.progress = "pulling_dropped_apk"
            pulled = False
            try:
                pulled = self.emulator.pull_file(remote_path, str(local_path))
            except Exception as e:
                print(f"Failed to pull dropped APK from {remote_path}: {e}")

            if not pulled or not local_path.exists() or local_path.stat().st_size == 0:
                entry["error"] = ("Could not retrieve this file from the device — it may "
                                   "have been deleted, moved, or the write hadn't finished "
                                   "when the scan ended.")
                results.append(entry)
                continue

            entry["local_path"] = str(local_path)

            self.progress = "analyzing_dropped_apk_static"
            try:
                entry["static"] = analyze_apk(str(local_path))
            except Exception as e:
                entry["static_error"] = f"Static analysis of dropped APK failed: {e}"
                results.append(entry)
                continue

            self.progress = "analyzing_dropped_apk_dynamic"
            try:
                entry["dynamic"] = self._run_nested_dynamic(
                    entry["static"], local_path, duration=min(30, total_duration)
                )
            except Exception as e:
                entry["dynamic_error"] = f"Dynamic analysis of dropped APK failed: {e}"

            # Give the dropped APK the exact same four-piece shape the
            # primary scan gets (static/network/correlation/verdict), so
            # the frontend can render it through the same full dashboard
            # rather than a condensed summary. If the nested dynamic pass
            # errored or never ran, fall back to an empty network report so
            # correlation/verdict still compute from static findings alone.
            dynamic_report = entry.get("dynamic")
            has_dynamic = bool(dynamic_report) and not dynamic_report.get("error")
            network_for_scoring = dynamic_report if has_dynamic else {
                "request_count": 0, "destinations": [], "beacons": [],
                "timeline": [], "network_score": 0, "behaviors": [], "evasion": {},
            }
            try:
                entry["correlation"] = correlate(entry["static"], network_for_scoring)
                entry["verdict"] = build_verdict(entry["static"], network_for_scoring, entry["correlation"])
            except Exception as e:
                entry["verdict_error"] = f"Could not compute a verdict for this dropped APK: {e}"
            entry["has_pcap"] = has_dynamic

            results.append(entry)

        return results

    def _run_nested_dynamic(self, dropped_static_report, apk_path, duration=30):
        """Install the dropped APK on the SAME already-booted emulator used
        for the parent run, watch it briefly with its own Frida hooks +
        network capture, then uninstall it. Deliberately not a full
        recursive DynamicAnalyzer — one level of "what does the dropped
        payload do" is what's useful for triage; chaining emulators inside
        emulators is not."""
        package_name = dropped_static_report.get("package")
        if not package_name:
            return {"error": "Could not determine the dropped APK's package name."}

        if not self.emulator.install_apk(str(apk_path)):
            return {"error": "Failed to install the dropped APK on the emulator."}

        nested_apk_snapshot_before = self.emulator.list_apk_files()
        nested_pkg_snapshot_before = self.emulator.list_packages()

        nested_pcap = str(self.output_dir / "dropped_apks" / f"{package_name.replace('.', '_')}_capture.pcap")
        nested_capture = RuntimeNetworkCapture(interface="any", output_file=nested_pcap)
        nested_capture.start_capture()

        nested_events = []
        nested_frida = FridaAgent(package_name)
        frida_active = False
        launch_method = None

        launch = dropped_static_report.get("launch_components") or {}
        launcher_activity = launch.get("launcher_activity")

        if launcher_activity:
            # Normal case: same spawn-gate flow as the parent app — hooks
            # are live before the process's first instruction runs.
            launch_method = f"launcher activity: {launcher_activity}"
            frida_active = nested_frida.start_monitoring(lambda ev: nested_events.append(ev))
            if not frida_active:
                self.emulator.launch_app(package_name, activity_name=launcher_activity)
        else:
            # No launcher — very common for a dropped second-stage payload,
            # which is usually built to run only as a background component,
            # not something a user is meant to tap. Start whatever exported
            # entry point exists instead, then attach Frida to the resulting
            # process (spawn-gating isn't possible here, since there's
            # nothing to spawn by package name alone).
            if launch.get("services"):
                svc = launch["services"][0]["name"]
                launch_method = f"service: {svc}"
                self.emulator.start_service(package_name, svc)
            elif launch.get("receivers"):
                rec = launch["receivers"][0]
                action = (rec.get("actions") or ["android.intent.action.MAIN"])[0]
                launch_method = f"receiver: {rec['name']} (action={action})"
                self.emulator.send_broadcast(package_name, rec["name"], action)
            elif launch.get("activities"):
                act = launch["activities"][0]["name"]
                launch_method = f"non-launcher activity: {act}"
                self.emulator.launch_app(package_name, activity_name=act)
            else:
                nested_capture.stop_capture()
                self.emulator.uninstall_apk(package_name)
                return {
                    "error": "This payload exposes no launcher activity, exported service, "
                             "exported receiver, or any other activity Third Eye could find to "
                             "start it with. It may only be triggerable via a component the "
                             "dropper app calls internally (e.g. a non-exported class invoked "
                             "directly through reflection/DexClassLoader), which can't be "
                             "started standalone from outside the process. Static analysis "
                             "above is still complete and valid.",
                    "launch_attempted": False,
                }

            time.sleep(2)  # give the component a moment to actually start
            pid = self.emulator.get_pid(package_name)
            if pid:
                frida_active = nested_frida.start_monitoring_attached(pid, lambda ev: nested_events.append(ev))

        time.sleep(3)
        self.emulator.simulate_user_interaction(duration)

        if frida_active:
            nested_frida.stop_monitoring()
        saved_pcap = nested_capture.stop_capture()

        nested_apk_snapshot_after = self.emulator.list_apk_files()
        nested_pkg_snapshot_after = self.emulator.list_packages()
        self.emulator.uninstall_apk(package_name)

        nested_network_report = analyze_pcap(saved_pcap) if saved_pcap else {
            "request_count": 0, "destinations": [], "beacons": [], "timeline": [], "network_score": 0,
        }

        behaviors, evasion_signals, further_dropped = _derive_behaviors_and_signals(
            nested_events, dropped_static_report
        )
        further_dropped = _merge_filesystem_dropped_apks(
            further_dropped, behaviors, nested_apk_snapshot_before, nested_apk_snapshot_after
        )
        further_dropped = _merge_package_installs(
            self.emulator, further_dropped, behaviors, package_name,
            nested_pkg_snapshot_before, nested_pkg_snapshot_after,
        )
        nested_network_report["behaviors"] = behaviors
        nested_network_report["evasion"] = _summarize_evasion(evasion_signals)
        nested_network_report["launch_method"] = launch_method
        nested_network_report["hooks_attached"] = frida_active
        if not frida_active:
            nested_network_report["note"] = (
                f"Started via {launch_method}, but Frida never attached — network capture "
                f"and the filesystem sweep above still ran, but runtime behavior hooks "
                f"(SMS, crypto, further drops via hooks, etc.) weren't live for this pass."
            )
        if further_dropped:
            # We stop the chain here rather than recursing again — surfaced
            # so an investigator knows there's a third stage worth a manual look.
            nested_network_report["further_dropped_apk_paths"] = list(further_dropped)

        return nested_network_report

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

            # Grant install-unknown-apps permission and set the sample as
            # the default launcher deterministically, via adb/RoleManager,
            # rather than gambling on simulate_user_interaction() randomly
            # tapping the right button on whatever system dialog happens to
            # be showing. Best-effort: neither is fatal to the run if the
            # device/API level doesn't support it.
            launcher_activity_for_setup = (self.static_report.get("launch_components") or {}).get("launcher_activity")
            self.emulator.grant_install_permission(package_name)
            self.emulator.set_as_default_launcher(package_name, activity_name=launcher_activity_for_setup)

            # Best-effort root, then a baseline sweep of .apk files already
            # on disk (the just-installed target's own base.apk copy will be
            # among these) — taken now, before the app runs, so the later
            # diff only shows files the app itself wrote during analysis.
            self.emulator.root_adb()
            apk_snapshot_before = self.emulator.list_apk_files()
            pkg_snapshot_before = self.emulator.list_packages()
            print(f"Filesystem sweep baseline: {len(apk_snapshot_before)} .apk file(s) found "
                  f"before running the sample.")

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
                # even without runtime instrumentation. Use the manifest's
                # actual launcher activity if we have one rather than the
                # generic monkey/LAUNCHER-category launch, which silently
                # does nothing on some builds even when a launcher exists.
                print("Frida unavailable - falling back to plain launch (no runtime hooks).")
                launcher_activity = (self.static_report.get("launch_components") or {}).get("launcher_activity")
                if launcher_activity:
                    print(f"Launching via manifest launcher activity: {launcher_activity}")
                    self.emulator.launch_app(package_name, activity_name=launcher_activity)
                else:
                    print("No launcher activity found in manifest - falling back to monkey launch "
                          "(this will do nothing if the app truly has no launcher).")
                    self.emulator.launch_app(package_name)

            time.sleep(5)  # let the app finish starting up
            if self.emulator.get_pid(package_name) is None:
                print(f"WARNING: '{package_name}' does not appear to be running after launch - "
                      f"the sample may not have started, which means it never got the chance to "
                      f"do anything (network traffic, drops, etc.) during this run.")

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

            behaviors, evasion_signals, dropped_apk_paths = _derive_behaviors_and_signals(
                self._frida_events, self.static_report
            )

            # Filesystem cross-check: take the "after" sweep now, while the
            # device is still up and before uninstall/reset, and diff it
            # against the baseline. This is the primary, mechanism-agnostic
            # detection — the Frida hooks above only corroborate it when the
            # dropper happens to use an API we hooked.
            apk_snapshot_after = self.emulator.list_apk_files()
            new_apk_files = apk_snapshot_after - apk_snapshot_before
            print(f"Filesystem sweep after run: {len(apk_snapshot_after)} .apk file(s) total, "
                  f"{len(new_apk_files)} new since baseline: {sorted(new_apk_files) or 'none'}")
            still_running = self.emulator.get_pid(package_name) is not None
            print(f"Sample process ({package_name}) still running at end of duration: {still_running}")
            dropped_apk_paths = _merge_filesystem_dropped_apks(
                dropped_apk_paths, behaviors, apk_snapshot_before, apk_snapshot_after
            )

            pkg_snapshot_after = self.emulator.list_packages()
            new_packages = pkg_snapshot_after - pkg_snapshot_before
            print(f"Installed-package diff: {len(new_packages)} new package(s) since baseline: "
                  f"{sorted(new_packages) or 'none'}")
            dropped_apk_paths = _merge_package_installs(
                self.emulator, dropped_apk_paths, behaviors, package_name,
                pkg_snapshot_before, pkg_snapshot_after,
            )

            network_report["behaviors"] = behaviors
            network_report["evasion"] = _summarize_evasion(evasion_signals)
            network_report["frida_installed"] = FRIDA_AVAILABLE

            # Chase down any second-stage APK the sample dropped, while it's
            # still sitting on the (not-yet-reset) device.
            network_report["dropped_apks"] = self._handle_dropped_apks(dropped_apk_paths, duration)

            self.progress = "cleaning_up"
            self.emulator.uninstall_apk(package_name)

        except Exception as e:
            error = str(e)
            print(f"Dynamic analysis error: {error}")
            network_report = {
                "request_count": 0, "destinations": [], "beacons": [], "timeline": [], "network_score": 0,
                "behaviors": [], "evasion": {"attempted": False, "confidence": "none", "signals": []},
                "dropped_apks": [], "frida_installed": FRIDA_AVAILABLE,
            }
        finally:
            if self.emulator:
                self.emulator.stop_emulator()
                # Reset the AVD back to a clean state so the APK just
                # installed (and anything it wrote/changed) doesn't persist
                # into the next scan. Runs even if analysis failed partway
                # through, since the device may still have the APK installed.
                self.progress = "resetting_device"
                try:
                    self.emulator.reset_device()
                except Exception as reset_err:
                    print(f"Warning: failed to reset emulator after analysis: {reset_err}")

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
