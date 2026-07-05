"""
frida_agent.py

Runtime API hooking via Frida. Uses Frida's spawn-gate pattern (spawn the
app suspended -> attach -> load hooks -> resume) so every hook is in place
before the app's first instruction runs. Attaching to an already-running
process (the original approach) misses anything that happens at startup and
throws if the process hasn't been launched yet.
"""

import time

try:
    import frida
except ImportError:
    frida = None

FRIDA_AVAILABLE = frida is not None


class FridaAgent:
    """Runtime API monitoring using Frida."""

    def __init__(self, package_name):
        self.package_name = package_name
        self.device = None
        self.pid = None
        self.session = None
        self.script = None
        self.events = []
        self.event_callback = None

    def spawn_and_attach(self):
        """Spawn the app suspended and attach, so hooks are live before the
        app's own code starts executing. Returns True on success."""
        if frida is None:
            print("frida is not installed; skipping runtime instrumentation.")
            return False
        try:
            self.device = frida.get_usb_device(timeout=10)
            self.pid = self.device.spawn([self.package_name])
            self.session = self.device.attach(self.pid)
            return True
        except Exception as e:
            print(f"Failed to spawn/attach: {e}")
            return False

    def attach_running(self, pid):
        """Attach to a process that's already running, rather than spawning
        it fresh. Used for payloads with no launcher activity — they get
        started via `am start-service`/`am broadcast` instead of a Frida
        spawn, so by the time we go looking there's already a pid to attach
        to, and there's nothing to resume(). Hooks won't cover whatever ran
        between process start and this attach, which is an unavoidable
        trade-off without a launcher to spawn-gate against."""
        if frida is None:
            print("frida is not installed; skipping runtime instrumentation.")
            return False
        try:
            self.device = frida.get_usb_device(timeout=10)
            self.pid = pid
            self.session = self.device.attach(pid)
            return True
        except Exception as e:
            print(f"Failed to attach to pid {pid}: {e}")
            return False

    def load_script(self):
        """Load the hook script into the (suspended) target process."""
        if self.session is None:
            return False

        script_code = """
        function installHooks() {
            Java.perform(function () {
                send({ hook_status: "Java bridge attached - installing hooks now." });

                var _hookOk = 0, _hookFail = 0;
                function safeHook(clsName, methodName, overloadArgs, onCall) {
                    try {
                        var cls = Java.use(clsName);
                        var method = overloadArgs ? cls[methodName].overload.apply(cls[methodName], overloadArgs) : cls[methodName];
                        method.implementation = onCall;
                        _hookOk += 1;
                    } catch (e) {
                        _hookFail += 1;
                        send({ hook_error: clsName + "#" + methodName + ": " + e });
                    }
                }

            // Network: HttpURLConnection
            safeHook("java.net.HttpURLConnection", "connect", null, function () {
                send("HTTP Connection: " + this.getURL());
                return this.connect();
            });

            // Network: raw sockets
            safeHook("java.net.Socket", "connect", ["java.net.SocketAddress", "int"], function (endpoint, timeout) {
                send("Socket connection: " + endpoint);
                return this.connect(endpoint, timeout);
            });

            // Crypto usage (often used to hide C2 traffic or exfiltrated data)
            safeHook("javax.crypto.Cipher", "doFinal", ["[B"], function (input) {
                send("Cipher operation");
                return this.doFinal(input);
            });

            // SharedPreferences reads — the *concrete* Android implementation
            // class is SharedPreferencesImpl, not the SharedPreferences
            // interface. Hooking the interface silently never fires.
            safeHook("android.app.SharedPreferencesImpl", "getString", ["java.lang.String", "java.lang.String"], function (key, defValue) {
                var value = this.getString(key, defValue);
                send("SP Read: " + key + " = " + value);
                return value;
            });

            // SMS send — classic banking-trojan / premium-fraud behavior
            safeHook("android.telephony.SmsManager", "sendTextMessage",
                ["java.lang.String", "java.lang.String", "java.lang.String", "android.app.PendingIntent", "android.app.PendingIntent"],
                function (dest, sc, text, sentIntent, deliveryIntent) {
                    send("SMS Sent to: " + dest + " | Text: " + text);
                    return this.sendTextMessage(dest, sc, text, sentIntent, deliveryIntent);
                });

            // File writes to flag exfiltration staging / sensitive-path access
            safeHook("java.io.FileOutputStream", "write", ["[B"], function (data) {
                send("File write: " + data.length + " bytes");
                return this.write(data);
            });

            // --- Dropper detection: local writes to a file ending in .apk ---
            // This is how we actually locate a second-stage payload on disk,
            // regardless of whether it arrived via DownloadManager, a raw
            // HTTP client, or anything else — they all eventually write bytes
            // to a file via one of these two FileOutputStream constructors.
            safeHook("java.io.FileOutputStream", "$init", ["java.lang.String", "boolean"], function (path, append) {
                if (path && path.toLowerCase().endsWith(".apk")) {
                    send("APK write: " + path);
                }
                return this.$init(path, append);
            });
            safeHook("java.io.FileOutputStream", "$init", ["java.io.File", "boolean"], function (file, append) {
                try {
                    var path = file.getAbsolutePath();
                    if (path && path.toLowerCase().endsWith(".apk")) {
                        send("APK write: " + path);
                    }
                } catch (e) {}
                return this.$init(file, append);
            });

            // --- Dropper detection: DownloadManager requests (corroborating signal) ---
            safeHook("android.app.DownloadManager$Request", "$init", ["android.net.Uri"], function (uri) {
                try {
                    send("Download request: " + uri.toString());
                } catch (e) {}
                return this.$init(uri);
            });

            // --- Dropper detection: silent self-install via PackageInstaller ---
            safeHook("android.content.pm.PackageInstaller$Session", "commit", ["android.content.IntentSender"], function (statusReceiver) {
                send("Package installer commit");
                return this.commit(statusReceiver);
            });

            // --- Anti-emulator: system property probing. Real apps almost
            // never query these specific keys; malware/sandbox-aware code
            // frequently does, to bail out or hide behavior when it detects
            // it's running inside an emulator. ---
            var EMULATOR_PROP_KEYWORDS = [
                "qemu", "goldfish", "ranchu", "vbox", "genymotion", "generic",
                "sdk_gphone", "microvirt", "andy", "nox", "ttve",
            ];
            safeHook("android.os.SystemProperties", "get", ["java.lang.String"], function (key) {
                var value = this.get(key);
                try {
                    var lowerKey = key.toLowerCase();
                    var lowerVal = (value || "").toLowerCase();
                    for (var i = 0; i < EMULATOR_PROP_KEYWORDS.length; i++) {
                        if (lowerKey.indexOf(EMULATOR_PROP_KEYWORDS[i]) !== -1 || lowerVal.indexOf(EMULATOR_PROP_KEYWORDS[i]) !== -1) {
                            send("System property check: " + key);
                            break;
                        }
                    }
                } catch (e) {}
                return value;
            });

            // --- Device fingerprinting: often paired with emulator checks
            // to confirm a real SIM/IMEI is present. ---
            safeHook("android.telephony.TelephonyManager", "getDeviceId", null, function () {
                send("Device fingerprint check: getDeviceId");
                return this.getDeviceId();
            });
            safeHook("android.telephony.TelephonyManager", "getSubscriberId", null, function () {
                send("Device fingerprint check: getSubscriberId");
                return this.getSubscriberId();
            });
            safeHook("android.telephony.TelephonyManager", "getSimSerialNumber", null, function () {
                send("Device fingerprint check: getSimSerialNumber");
                return this.getSimSerialNumber();
            });

            // --- Anti-emulator: presence checks for known emulator-only artifacts ---
            var EMULATOR_ARTIFACT_PATHS = [
                "/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace",
                "/system/bin/qemu-props", "/dev/socket/qemud", "/dev/qemu_pipe",
                "/system/bin/androVM-prop", "/system/bin/microvirt-prop",
            ];
            safeHook("java.io.File", "exists", null, function () {
                var result = this.exists();
                try {
                    var path = this.getAbsolutePath();
                    for (var i = 0; i < EMULATOR_ARTIFACT_PATHS.length; i++) {
                        if (path.indexOf(EMULATOR_ARTIFACT_PATHS[i]) !== -1) {
                            send("Emulator artifact check: " + path);
                            break;
                        }
                    }
                } catch (e) {}
                return result;
            });

            // --- Anti-emulator / root: shell command probing (getprop, su) ---
            safeHook("java.lang.Runtime", "exec", ["java.lang.String"], function (cmd) {
                if (cmd && (cmd.indexOf("getprop") !== -1 || cmd.indexOf("su") !== -1)) {
                    send("Shell command: " + cmd);
                }
                return this.exec(cmd);
            });

            send({ hook_status: "Hook installation complete: " + _hookOk + " succeeded, " + _hookFail + " failed." });
            });
        }

        // On a freshly-spawned process, the ART Java runtime isn't always
        // attached yet by the time this script starts running, which makes
        // the global `Java` object undefined and throws
        // "ReferenceError: Java is not defined" if we call Java.perform()
        // immediately. Poll for it instead of assuming it's ready.
        var _attempts = 0;
        function waitForJavaAndHook() {
            if (typeof Java !== "undefined" && Java.available) {
                installHooks();
                return;
            }
            _attempts += 1;
            if (_attempts > 50) {  // ~10s at 200ms — give up rather than loop forever
                send({ hook_error: "Java runtime never became available in this process; hooks not installed." });
                return;
            }
            setTimeout(waitForJavaAndHook, 200);
        }
        waitForJavaAndHook();
        """

        self.script = self.session.create_script(script_code)
        self.script.on("message", self._on_message)
        self.script.load()
        return True

    def resume(self):
        """Resume the spawned (suspended) process now that hooks are loaded."""
        if self.device and self.pid:
            self.device.resume(self.pid)

    def _on_message(self, message, data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                if "hook_error" in payload:
                    print(f"Frida hook failed to install: {payload['hook_error']}")
                elif "hook_status" in payload:
                    print(f"Frida: {payload['hook_status']}")
            event = {"timestamp": time.time(), "message": payload}
            self.events.append(event)
            if self.event_callback:
                self.event_callback(event)
        elif message.get("type") == "error":
            print(f"Frida script error: {message.get('description', message)}")

    def start_monitoring(self, callback=None):
        """Full spawn -> attach -> hook -> resume sequence. Returns True if
        the app is now running with hooks live."""
        self.event_callback = callback
        self.events = []
        if not self.spawn_and_attach():
            return False
        if not self.load_script():
            return False
        self.resume()
        return True

    def start_monitoring_attached(self, pid, callback=None):
        """Attach-only counterpart to `start_monitoring()`, for a process
        that's already running (started via `am start-service` or
        `am broadcast` because it has no launcher activity to spawn).
        Returns True if hooks are now live in that process."""
        self.event_callback = callback
        self.events = []
        if not self.attach_running(pid):
            return False
        return self.load_script()

    def stop_monitoring(self):
        try:
            if self.script:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session:
                self.session.detach()
        except Exception:
            pass
