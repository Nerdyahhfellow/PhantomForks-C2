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

    def load_script(self):
        """Load the hook script into the (suspended) target process."""
        if self.session is None:
            return False

        script_code = """
        Java.perform(function () {
            function safeHook(clsName, methodName, overloadArgs, onCall) {
                try {
                    var cls = Java.use(clsName);
                    var method = overloadArgs ? cls[methodName].overload.apply(cls[methodName], overloadArgs) : cls[methodName];
                    method.implementation = onCall;
                } catch (e) {
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
        });
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
