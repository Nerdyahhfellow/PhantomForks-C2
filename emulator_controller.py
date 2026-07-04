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


class AndroidEmulatorController:
    """Control Android emulator for dynamic analysis."""

    def __init__(self, avd_name="test_avd", adb_path="adb"):
        self.avd_name = avd_name
        self.adb_path = adb_path
        self.emulator_process = None
        self.device_ready = False

    def start_emulator(self, timeout=120):
        """Start Android emulator and block until boot completes."""
        print(f"Starting emulator: {self.avd_name}")
        try:
            self.emulator_process = subprocess.Popen(
                ["emulator", "-avd", self.avd_name, "-no-snapshot", "-no-audio", "-no-window"],
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
