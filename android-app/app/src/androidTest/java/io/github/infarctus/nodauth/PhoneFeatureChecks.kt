package io.github.infarctus.nodauth

import androidx.test.platform.app.InstrumentationRegistry
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.*
import org.junit.Test
import org.junit.Assume.assumeTrue
import com.chaquo.python.Python
import com.chaquo.python.PyObject
import java.io.File

/** Isolated state and public APK/expired QR fixtures; no Microsoft activation. */
class PhoneFeatureChecks {
    companion object { private var publicConfig: PyObject? = null }

    private fun config(): PyObject {
        publicConfig?.let { return it }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val apk = File(context.cacheDir, "native-apk-check.apk")
        assumeTrue("Public APK fixture was not supplied", apk.isFile)
        val deadline = System.currentTimeMillis() + 15000
        val application = context.applicationContext as NodAuthApplication
        while (!application.controller.ready && System.currentTimeMillis() < deadline) Thread.sleep(50)
        assertTrue(application.controller.ready)
        val python = Python.getInstance()
        val certs = ApkIdentity.fingerprints(context, apk.absolutePath)
        val signatures = python.getModule("json").callAttr("loads", certs)
        return python.getModule("app.extract_apk_config").callAttr("extract_config", apk.absolutePath, signatures)
            .also { publicConfig = it }
    }

    @Test fun encryptedBackupWorksOnAndroidAndRejectsWrongPassword() {
        val plain = "synthetic backup test".toByteArray()
        val archive = BackupCrypto.encrypt(plain, "sample-password-2026")
        assertArrayEquals(plain, BackupCrypto.decrypt(archive, "sample-password-2026"))
        assertThrows(Exception::class.java) { BackupCrypto.decrypt(archive, "different-password") }
    }
    @Test fun qrDecoderReadsMicrosoftShapeWithoutContactingIt() {
        val raw = "https://login.microsoftonline.com/authenticatorApp/activateAccount?accountType=mfa&source=qrCode&code=012345678&url=https%3A%2F%2Fmobileappcommunicator.auth.microsoft.com%2Factivatev2%2F123456789%2FSAMPLE"
        val matrix = QRCodeWriter().encode(raw, BarcodeFormat.QR_CODE, 770, 770)
        val pixels = IntArray(770 * 770) { index -> if (matrix[index % 770, index / 770]) 0xff000000.toInt() else 0xffffffff.toInt() }
        assertEquals(raw, QrDecoder.decodePixels(770, 770, pixels))
    }
    @Test fun suppliedExpiredQrImageDecodesAndValidatesLocally() {
        config()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val image = File(context.cacheDir, "native-qr-check-image")
        assumeTrue("Expired QR fixture was not supplied", image.isFile)
        val raw = QrDecoder.decodeBytes(image.readBytes())
        val summary = Python.getInstance().getModule("enrollment_qr").callAttr("qr_summary", raw)
        assertEquals("mobileappcommunicator.auth.microsoft.com", summary.toString())
    }
    @Test fun nativeAndroidTlsGetsPublicMicrosoftMetadata() {
        assertEquals(200, AndroidHttpTransport.publicCheck())
    }
    @Test fun foreignApkIsRejectedBeforeEnrollment() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertThrows(Exception::class.java) { ApkIdentity.fingerprints(context, context.applicationInfo.sourceDir) }
    }
    @Test fun originalApkExtractsOnAndroidWithoutOpensslOrEnrollmentChanges() {
        val cfg = config()
        assertTrue(cfg.callAttr("get", "signing_cert_sha1").asList().isNotEmpty())
        assertEquals("com.azure.authenticator", cfg.callAttr("get", "package").toString())
        assertTrue(cfg.callAttr("get", "firebase").callAttr("get", "sender_id").toString().isNotEmpty())
    }

    @Test fun freshGoogleRegistrationUsesIsolatedStateAndNativeHttp() {
        val cfg = config()
        val python = Python.getInstance()
        val scope = python.getModule("builtins").callAttr("dict")
        scope.callAttr("__setitem__", "config", cfg)
        scope.callAttr("__setitem__", "cache_path", InstrumentationRegistry.getInstrumentation().targetContext.cacheDir.absolutePath)
        python.getModule("builtins").callAttr("exec", """
import os, tempfile
from app import fcm
from app.state import save_json
from app.fcm_lifecycle import FcmError
old_dir = os.environ['AUTH_STATE_DIR']
try:
    with tempfile.TemporaryDirectory(dir=cache_path) as temporary:
        os.environ['AUTH_STATE_DIR'] = temporary
        save_json('apk_config.json', config)
        try:
            device = fcm.do_checkin()
            token = fcm.do_register(device)
            success = bool(token and device['androidId'] and device['securityToken'])
        except (Exception, SystemExit) as exc:
            detail = exc.diagnostic if isinstance(exc, FcmError) else type(exc).__name__
            raise AssertionError('Native Google registration failed: ' + detail) from None
finally:
    os.environ['AUTH_STATE_DIR'] = old_dir
""".trimIndent(), scope)
        assertTrue(scope.callAttr("get", "success").toBoolean())
    }

    @Test fun sqliteBackupExportsAndRestoresInIsolatedAndroidStorage() {
        config() // Wait for the runtime, without opening the approval activity.
        val python = Python.getInstance()
        val scope = python.getModule("builtins").callAttr("dict")
        scope.callAttr("__setitem__", "cache_path", InstrumentationRegistry.getInstrumentation().targetContext.cacheDir.absolutePath)
        python.getModule("builtins").callAttr("exec", """
import os, tempfile
from pathlib import Path
from mobile_runtime import MobileRuntime
from app.registration import RegistrationState
from app.state import save_json
old_dir = os.environ['AUTH_STATE_DIR']
try:
    with tempfile.TemporaryDirectory(dir=cache_path) as temporary:
        runtime = MobileRuntime(temporary)
        save_json('apk_config.json', {'package': 'com.azure.authenticator', 'version_name': '6.2609.0',
                  'firebase': {'api_key': 'synthetic', 'app_id': 'app', 'sender_id': 'sender', 'project': 'project'}})
        save_json('checkin_info.json', {'androidId': 123, 'securityToken': 456})
        registry = RegistrationState()
        try:
            registry.google_success('SYNTHETIC')
            candidate = registry.begin_enrollment('SYNTHETIC')
            registry.stage_activation(candidate, {'ActivateNewResult': True, 'TenantId': 'tenant', 'AzureObjectId': 'object'})
            registry.confirm_staged(candidate)
        finally:
            registry.close()
        archive = Path(temporary) / 'synthetic.zip'
        runtime.export_setup(str(archive))
        runtime.import_setup(str(archive))
        success = (runtime.state_dir / 'activation.pending.json').is_file()
finally:
    os.environ['AUTH_STATE_DIR'] = old_dir
""".trimIndent(), scope)
        assertTrue(scope.callAttr("get", "success").toBoolean())
    }
}
