Java.perform(function () {
    console.log("[*] Frida Universal Root & SSL Pinning Bypass Loaded...");

    // === Developer Mode Bypass ===
    try {
        var settingSecure = Java.use('android.provider.Settings$Secure');
        var settingGlobal = Java.use('android.provider.Settings$Global');

        settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, name, def) {
            console.log("[+] Bypassed Secure.getInt(cr, " + name + ")");
            return 0;
        };
        settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, name) {
            console.log("[+] Bypassed Secure.getInt(cr, " + name + ")");
            return 0;
        };
        settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, name, def) {
            console.log("[+] Bypassed Global.getInt(cr, " + name + ")");
            return 0;
        };
        settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, name) {
            console.log("[+] Bypassed Global.getInt(cr, " + name + ")");
            return 0;
        };
    } catch (err) {
        console.log("[!] Developer mode bypass failed: " + err);
    }

    // === Device Info Spoofing ===
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getSubscriberId.implementation = function () {
            console.log("[+] getSubscriberId spoofed!");
            return "123456789012345";
        };
        TelephonyManager.getSimSerialNumber.implementation = function () {
            console.log("[+] getSimSerialNumber spoofed!");
            return "FAKESERIAL12345";
        };
    } catch (err) {
        console.log("[!] TelephonyManager spoof failed: " + err);
    }

    // === Root Detection Bypass ===
    try {
        var RootCheckClass = Java.use("ah.e0");
        RootCheckClass.b.implementation = function () {
            console.log("[+] Root detection method ah.e0.b() bypassed!");
            return false;
        };
    } catch (err) {
        console.log("[!] Root class hook failed: " + err);
    }

    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (path.includes("su") || path.includes("magisk") || path.includes("busybox")) {
                console.log("[+] Bypassing root file existence check: " + path);
                return false;
            }
            return this.exists();
        };
    } catch (err) {
        console.log("[!] File.exists hook failed: " + err);
    }

    // === SSL Pinning Bypass (Multiple Layers) ===
    try {
        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        X509Certificate.checkValidity.implementation = function () {
            console.log("[+] X509Certificate.checkValidity() bypassed!");
        };
    } catch (err) {
        console.log("[!] X509Certificate hook failed: " + err);
    }

    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function () {
            console.log("[+] TrustManagerImpl.verifyChain() bypassed!");
            return [];
        };
    } catch (err) {
        console.log("[!] TrustManagerImpl hook failed: " + err);
    }

    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setSSLSocketFactory.implementation = function () {
            console.log("[+] Bypassed setSSLSocketFactory()");
        };
    } catch (err) {
        console.log("[!] HttpsURLConnection hook failed: " + err);
    }

    // === SSLContext TrustManager Injection ===
    try {
        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var BufferedInputStream = Java.use("java.io.BufferedInputStream");
        var KeyStore = Java.use("java.security.KeyStore");
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        console.log("[*] Attempting SSLContext TrustManager injection...");
        var cf = CertificateFactory.getInstance("X.509");
        var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
        var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
        var ca = cf.generateCertificate(bufferedInputStream);
        bufferedInputStream.close();

        var keyStoreType = KeyStore.getDefaultType();
        var keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);

        var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function (km, tm, sr) {
            console.log("[+] Overriding SSLContext.init() with custom TrustManager!");
            this.init(km, tmf.getTrustManagers(), sr);
        };
    } catch (err) {
        console.log("[!] SSLContext TrustManager injection failed: " + err);
    }

    console.log("[*] All hooks injected successfully!");
});
