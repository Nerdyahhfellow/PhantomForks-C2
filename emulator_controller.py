"""
emulator_controller.py

Controls an Android emulator instance for dynamic APK analysis: boot, install,
launch, simulate interaction, capture logs/screenshots, and clean up.

This is a fixed version of the original `and_automation.py` — the class
itself was already reasonably solid, no functional bugs were found here.
It's renamed to `emulator_controller.py` so its filename matches its class
name and content, consistent with the rest of the flat project.
"""

import subprocess
import time
import random
import os


class AndroidEmulatorController:
    """Control Android emulator for dynamic analysis."""

    def __init__(self, avd_name="test_avd", adb_path="adb"):
        self.avd_name = avd_name
        self.adb_path = adb_path
        self.emulator_process = None
        self.device_ready = False
        self._rooted = False

    def start_emulator(self, timeout=120, wipe_data=False):
        """Start Android emulator and block until boot completes.

        By default this is a normal warm boot. The device is expected to
        already be clean because `reset_device()` is run after every dynamic
        analysis job finishes (see `dynamic_analysis.py`). Pass
        `wipe_data=True` to force a fresh wipe on this boot too (e.g. for the
        very first run, or if you want extra insurance) — a wiped boot takes
        noticeably longer, which is why it isn't the default here.
        """
        print(f"Starting emulator: {self.avd_name}" + (" (wiping data)" if wipe_data else ""))
        args = ["emulator", "-avd", self.avd_name, "-no-audio", "-no-window"]
        if wipe_data:
            args.append("-wipe-data")
        else:
            args.append("-no-snapshot")
        try:
            self.emulator_process = subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "Could not find the 'emulator' executable. Install the Android SDK "
                "emulator package and add its folder (e.g. "
                "%LOCALAPPDATA%\\Android\\Sdk\\emulator on Windows, or "
                "$ANDROID_SDK_ROOT/emulator on macOS/Linux) to your PATH, then restart "
                "the app."
            )

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(
                    [self.adb_path, "shell", "getprop", "sys.boot_completed"],
                    capture_output=True, text=True,
                )
            except FileNotFoundError:
                raise RuntimeError(
                    "Could not find the 'adb' executable. Install the Android SDK "
                    "platform-tools package and add its folder (e.g. "
                    "%LOCALAPPDATA%\\Android\\Sdk\\platform-tools on Windows, or "
                    "$ANDROID_SDK_ROOT/platform-tools on macOS/Linux) to your PATH, "
                    "then restart the app."
                )
            if result.stdout.strip() == "1":
                self.device_ready = True
                print("Emulator ready")
                return True
            time.sleep(5)
        return False

    def stop_emulator(self):
        """Stop emulator and clean up the subprocess."""
        if self.emulator_process:
            self.emulator_process.terminate()
            try:
                self.emulator_process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.emulator_process.kill()
            self.emulator_process = None
        self.device_ready = False

    def reset_device(self, timeout=180):
        """Wipe the AVD's user-data partition back to a clean state.

        Boots the AVD once with `-wipe-data` and waits for that wiped boot to
        finish (so the wipe is actually committed), then shuts it straight
        back down. Call this after a dynamic analysis run completes so the
        APK that was just installed — and any files/settings it touched — is
        gone before the device is used again, rather than silently
        accumulating across scans.
        """
        print(f"Resetting emulator '{self.avd_name}' to a clean state (wipe-data)...")
        try:
            wipe_process = subprocess.Popen(
                ["emulator", "-avd", self.avd_name, "-wipe-data", "-no-audio", "-no-window"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            print("Could not find the 'emulator' executable while resetting; skipping reset.")
            return False

        booted = False
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(
                    [self.adb_path, "shell", "getprop", "sys.boot_completed"],
                    capture_output=True, text=True,
                )
            except FileNotFoundError:
                break
            if result.stdout.strip() == "1":
                booted = True
                break
            time.sleep(5)

        wipe_process.terminate()
        try:
            wipe_process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            wipe_process.kill()

        if booted:
            print(f"Emulator '{self.avd_name}' reset complete — device is back to a clean state.")
        else:
            print(f"Emulator '{self.avd_name}' reset timed out; state for the next run is uncertain.")
        return booted

    def root_adb(self):
        """Best-effort attempt to restart adbd as root. Only affects whether
        the filesystem sweep in `list_apk_files()` can see into other apps'
        private data directories (/data/data/<pkg>) — everything under
        /sdcard and /data/local/tmp is visible either way. Many stock/
        Play-Store emulator images refuse this silently, which is fine; the
        sweep just covers less ground. Never raises."""
        self._rooted = False
        try:
            result = subprocess.run(
                [self.adb_path, "root"], capture_output=True, text=True, timeout=15,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("adb root: could not run adb (not on PATH or timed out).")
            return False
        combined = (result.stdout + result.stderr).lower()
        if "cannot run as root" in combined or "production builds" in combined:
            print(f"adb root: device refused ({(result.stdout + result.stderr).strip()!r}) "
                  f"- filesystem sweep will skip /data/data and /data/user/0.")
            return False
        time.sleep(2)  # give adbd a moment to restart after switching to root
        self._rooted = True
        print("adb root: succeeded - filesystem sweep will also cover /data/data and /data/user/0.")
        return True

    def list_apk_files(self):
        """Sweep common on-device locations for any file ending in `.apk`
        and return the set of absolute paths found.

        This exists as a filesystem-level, API-agnostic cross-check for
        dropped/second-stage APKs. Frida hooks on specific write APIs
        (FileOutputStream, etc.) can miss real-world droppers that write via
        buffered/byte-range writes, Okio, java.nio, native code through JNI,
        a download-to-temp-name-then-renameTo(".apk") pattern, or by
        shelling out to `pm install` directly — none of which is guaranteed
        to trip a fixed set of hooked methods. A file appearing on disk is
        the one thing all of those approaches have in common, so diffing a
        before/after snapshot of this sweep (see `dynamic_analysis.py`)
        catches the drop no matter which mechanism produced it.

        NOTE: this alone still misses a dropper that installs its payload
        via a `PackageInstaller` session (write bytes into the session,
        then `commit()`) on a device where `root_adb()` failed — the staged
        file never lands as a plain `*.apk` path outside of `/data/app`,
        which this sweep can only see when rooted. `list_packages()` /
        `get_apk_path_for_package()` below cover that case without needing
        root at all, by diffing what's *installed* rather than what's on
        disk.
        """
        search_roots = ["/sdcard", "/storage/emulated/0", "/data/local/tmp"]
        if self._rooted:
            # /data/app is where PackageInstaller sessions land once
            # committed — the modern silent-install path (write bytes into
            # a session, then `commit()`) never touches a plain .apk file
            # anywhere else, so this is essential for catching that
            # technique specifically, not just a nice-to-have.
            search_roots += ["/data/data", "/data/user/0", "/data/app"]

        found = set()
        for root in search_roots:
            try:
                result = subprocess.run(
                    [self.adb_path, "shell", "find", root, "-iname", "*.apk"],
                    capture_output=True, text=True, timeout=30,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            for line in result.stdout.splitlines():
                path = line.strip()
                # `find` on a locked-down dir without root prints
                # "Permission denied" to stdout on some Android builds
                # instead of stderr — filter that noise out.
                if path and path.lower().endswith(".apk") and "permission denied" not in path.lower():
                    found.add(path)
        return found

    def list_packages(self):
        """Return the set of package names currently installed on the
        device, via `pm list packages`. Unlike `list_apk_files()`, this
        needs no root at all — `pm` is queryable over a plain adb shell.

        Diffing this before/after a run is what actually catches a dropper
        that silently installs its payload through a `PackageInstaller`
        session rather than writing a loose `.apk` file: the moment
        `commit()` succeeds, the new package shows up here, whether or not
        the device is rooted and regardless of where PackageManager staged
        the underlying file."""
        try:
            result = subprocess.run(
                [self.adb_path, "shell", "pm", "list", "packages"],
                capture_output=True, text=True, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return set()
        packages = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.add(line[len("package:"):].strip())
        return packages

    def get_apk_path_for_package(self, package_name):
        """Resolve the on-device path(s) of an installed package's base
        APK via `pm path`, so a newly-appeared package (caught by
        `list_packages()`) can be pulled down for static/dynamic analysis
        without needing root. Returns the first (base) path, or None if the
        package can't be resolved (e.g. it was uninstalled again already)."""
        try:
            result = subprocess.run(
                [self.adb_path, "shell", "pm", "path", package_name],
                capture_output=True, text=True, timeout=15,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                return line[len("package:"):].strip()
        return None

    def pull_file(self, remote_path, local_path):
        """Pull a file off the device (e.g. a dropped/downloaded APK) to
        `local_path` on the host. Returns True if the file ended up on disk
        with non-zero size."""
        try:
            subprocess.run(
                [self.adb_path, "pull", remote_path, local_path],
                capture_output=True, text=True, timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            print(f"Failed to pull '{remote_path}': {e}")
            return False
        return os.path.exists(local_path) and os.path.getsize(local_path) > 0

    def install_apk(self, apk_path):
        result = subprocess.run(
            [self.adb_path, "install", "-r", apk_path],
            capture_output=True, text=True,
        )
        return "Success" in result.stdout

    def uninstall_apk(self, package_name):
        subprocess.run([self.adb_path, "uninstall", package_name], capture_output=True, text=True)

    def launch_app(self, package_name, activity_name=None):
        if activity_name:
            cmd = [self.adb_path, "shell", "am", "start", "-n", f"{package_name}/{activity_name}"]
        else:
            cmd = [self.adb_path, "shell", "monkey", "-p", package_name,
                   "-c", "android.intent.category.LAUNCHER", "1"]
        subprocess.run(cmd, capture_output=True, text=True)

    def start_service(self, package_name, service_name):
        """Explicitly start a service component. Used for dropped payloads
        that have no launcher activity — very common, since a second-stage
        payload is usually designed to run in the background rather than
        present a UI a user would tap."""
        subprocess.run(
            [self.adb_path, "shell", "am", "start-service", "-n", f"{package_name}/{service_name}"],
            capture_output=True, text=True,
        )

    def send_broadcast(self, package_name, receiver_name, action):
        """Explicitly deliver an intent to a specific receiver component.
        Used to trigger payloads whose only real entry point is a
        BroadcastReceiver (e.g. BOOT_COMPLETED-style persistence)."""
        subprocess.run(
            [self.adb_path, "shell", "am", "broadcast", "-a", action, "-n", f"{package_name}/{receiver_name}"],
            capture_output=True, text=True,
        )

    def get_pid(self, package_name):
        """Return the numeric pid of a currently-running process for
        `package_name`, or None if it isn't running. Used to attach Frida
        after starting a service/receiver externally, since there's nothing
        to spawn-gate in that case — the process already exists by the time
        we go looking for it."""
        try:
            result = subprocess.run(
                [self.adb_path, "shell", "pidof", package_name],
                capture_output=True, text=True, timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        parts = result.stdout.strip().split()
        return int(parts[0]) if parts and parts[0].isdigit() else None

    def capture_screen(self, output_path="screenshot.png"):
        subprocess.run([self.adb_path, "exec-out", "screencap", "-p", output_path], capture_output=True)

    def get_logcat(self, lines=1000):
        result = subprocess.run(
            [self.adb_path, "logcat", "-d", "-t", str(lines)],
            capture_output=True, text=True,
        )
        return result.stdout

    def clear_logcat(self):
        subprocess.run([self.adb_path, "logcat", "-c"], capture_output=True)

    def simulate_user_interaction(self, duration=30):
        """Fire random taps/swipes for `duration` seconds to trigger app behavior
        that only happens after user interaction (many banking trojans/spyware
        stay dormant until the user actually touches the screen)."""
        end_time = time.time() + duration
        while time.time() < end_time:
            x = random.randint(100, 700)
            y = random.randint(200, 1200)
            subprocess.run([self.adb_path, "shell", "input", "tap", str(x), str(y)], capture_output=True)
            time.sleep(random.uniform(1, 5))

            if random.random() < 0.2:
                x1, y1 = random.randint(100, 400), random.randint(200, 600)
                x2, y2 = random.randint(300, 700), random.randint(400, 1000)
                subprocess.run(
                    [self.adb_path, "shell", "input", "swipe", str(x1), str(y1), str(x2), str(y2), "500"],
                    capture_output=True,
                )
                time.sleep(random.uniform(0.5, 2))
