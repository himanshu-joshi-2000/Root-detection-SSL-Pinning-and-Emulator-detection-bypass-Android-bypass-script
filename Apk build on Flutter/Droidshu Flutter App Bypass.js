// flutter_bypass.js

console.log("[*] Flutter SSL Pinning & Root Detection Bypass Script Loaded");

Java.perform(function () {

    // ----------- Developer Mode Bypass -----------
    try {
        var settingSecure = Java.use('android.provider.Settings$Secure');
        settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
            console.log("[*] Bypassing Secure.getInt with default: " + name);
            return 0;
        };
        settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
            console.log("[*] Bypassing Secure.getInt: " + name);
            return 0;
        };

        var settingGlobal = Java.use('android.provider.Settings$Global');
        settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, def) {
            console.log("[*] Bypassing Global.getInt with default: " + name);
            return 0;
        };
        settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
            console.log("[*] Bypassing Global.getInt: " + name);
            return 0;
        };
    } catch (e) {
        console.log("[!] Developer mode bypass failed: " + e);
    }

    // ----------- Telephony Spoofing -----------
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getSubscriberId.implementation = function () {
            console.log("[*] Spoofing getSubscriberId");
            return "123456789012345";
        };
        TelephonyManager.getSimSerialNumber.implementation = function () {
            console.log("[*] Spoofing getSimSerialNumber");
            return "FAKESERIAL12345";
        };
    } catch (e) {
        console.log("[!] Telephony spoofing failed: " + e);
    }

    // ----------- Root Detection Bypass -----------
    try {
        var RootCheck = Java.use("ah.e0");
        RootCheck.b.implementation = function () {
            console.log("[*] Bypassing RootCheck.b()");
            return false;
        };
    } catch (e) {
        console.log("[!] Custom root check class bypass failed: " + e);
    }

    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || path.indexOf("magisk") !== -1 || path.indexOf("busybox") !== -1) {
                console.log("[*] Root file detection bypass: " + path);
                return false;
            }
            return this.exists();
        };
    } catch (e) {
        console.log("[!] File.exists root detection hook failed: " + e);
    }

    // ----------- SSL Pinning Bypass (General) -----------
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function () {
            console.log("[*] Bypassing TrustManagerImpl.verifyChain()");
            return [];
        };

        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        X509Certificate.checkValidity.implementation = function () {
            console.log("[*] Bypassing X509Certificate.checkValidity()");
        };

        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setSSLSocketFactory.implementation = function (sf) {
            console.log("[*] Bypassing setSSLSocketFactory()");
        };
    } catch (e) {
        console.log("[!] General SSL pinning bypass failed: " + e);
    }

}); // End of Java.perform

// ----------- Flutter TLS Patch (Pattern Hook) -----------
setTimeout(function () {
    var pattern = "ff 03 05 d1 fd 7b 0f a9 bc de 05 94 08 0a 80 52 48";
    var module = "libflutter.so";
    var expectedReturnValue = true;

    console.log("[*] Flutter SSL pinning patch starting");

    Process.enumerateModules().forEach(function (mod) {
        if (mod.name === module) {
            console.log("[*] Flutter lib found: " + mod.base + " | Size: " + mod.size);
            Memory.scanSync(mod.base, mod.size, pattern).forEach(function (res) {
                var addr = res.address;
                console.log("[+] Hooking SSL check at: " + addr);

                Interceptor.attach(addr, {
                    onLeave: function (retval) {
                        console.log("[*] Flutter TLS patched: changed return from " + retval + " to " + expectedReturnValue);
                        retval.replace(+expectedReturnValue);
                    }
                });
            });
        }
    });
}, 1000);
