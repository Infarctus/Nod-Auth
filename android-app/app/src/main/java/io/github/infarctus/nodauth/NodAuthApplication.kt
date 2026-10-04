package io.github.infarctus.nodauth

import android.app.Application
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import android.net.Uri
import java.io.File

class NodAuthApplication : Application() {
    lateinit var controller: RuntimeController
    override fun onCreate() {
        super.onCreate()
        controller = RuntimeController(this)
    }
}

class RuntimeController(private val app: Application) {
    private val executor = Executors.newSingleThreadScheduledExecutor()
    private val operations = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var runtime: PyObject? = null
    private var previousSnapshot = ""
    var state by mutableStateOf(JSONObject().put("status", "Starting…"))
        private set
    var ready by mutableStateOf(false)
        private set
    var busy by mutableStateOf(false)
        private set

    init {
        executor.execute {
            try {
                app.cacheDir.listFiles()?.filter {
                    it.isFile && (it.name.startsWith("nod-auth-") || it.name == "setup-import.zip")
                }?.forEach { it.delete() }
                if (!Python.isStarted()) Python.start(AndroidPlatform(app))
                runtime = Python.getInstance().getModule("mobile_runtime")
                    .callAttr("MobileRuntime", app.filesDir.absolutePath)
                runtime?.callAttr("use_android_transport")
                refresh()
                main.post { ready = true }
                // Public discovery document only: this never triggers an MFA action.
                Executors.newSingleThreadExecutor().execute {
                    runtime?.callAttr("diagnostics")
                }
            } catch (_: Exception) {
                main.post { state = JSONObject().put("status", "Runtime could not start")
                    .put("message", "The Python runtime failed to load. Check the development logs.") }
            }
        }
        executor.scheduleWithFixedDelay({ refresh() }, 250, 250, TimeUnit.MILLISECONDS)
    }

    private fun refresh() {
        try {
            val raw = runtime?.callAttr("snapshot")?.toString() ?: return
            if (raw == previousSnapshot) return
            previousSnapshot = raw
            val snapshot = JSONObject(raw)
            main.post { state = snapshot }
        } catch (_: Exception) {
            main.post { state = JSONObject().put("status", "Runtime unavailable") }
        }
    }

    fun start() { executor.execute { runtime?.callAttr("start"); refresh() } }
    fun stop() { executor.execute { runtime?.callAttr("stop"); refresh() } }
    fun answer(id: String, value: String, unlocked: Boolean) {
        executor.execute { runtime?.callAttr("answer", id, value, unlocked); refresh() }
    }

    private fun operation(failure: String, complete: (Boolean, String) -> Unit, work: () -> String) {
        if (busy || !ready) { complete(false, "Wait for the current operation to finish."); return }
        busy = true
        operations.execute {
            var success = false
            var message = failure
            try {
                message = work()
                success = true
            } catch (_: Exception) {
                // Exception text may contain enrollment material. Use fixed UI text.
            } finally {
                executor.execute {
                    refresh()
                    main.post { busy = false; complete(success, message) }
                }
            }
        }
    }

    private fun temporary(suffix: String): File = File.createTempFile("nod-auth-", suffix, app.cacheDir)
        .also { android.system.Os.chmod(it.absolutePath, 0b110000000) }

    private fun copyInput(uri: Uri, file: File, limit: Int) {
        app.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input)
            file.outputStream().use { output ->
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= limit)
                    output.write(buffer, 0, count)
                }
            }
        }
    }

    fun prepareApk(uri: Uri, complete: (Boolean, String) -> Unit) =
        operation("Could not read the APK. Choose the original Microsoft Authenticator APK while disconnected.", complete) {
            val apk = temporary(".apk")
            try {
                copyInput(uri, apk, 256 * 1024 * 1024)
                val certificates = ApkIdentity.fingerprints(app, apk.absolutePath)
                val version = runtime!!.callAttr("prepare_apk", apk.absolutePath, certificates).toString()
                "APK configuration ready ($version)."
            } finally { apk.delete() }
        }

    fun inspectQr(raw: String, complete: (Boolean, String) -> Unit) =
        operation("Use a supported Microsoft work or school MFA setup QR code.", complete) {
            runtime!!.callAttr("inspect_qr", raw).toString()
        }

    fun readQrImage(uri: Uri, complete: (Boolean, String) -> Unit) =
        operation("Could not read a QR code from this image. Try the camera scanner.", complete) {
            val bytes = app.contentResolver.openInputStream(uri).use { requireNotNull(it).readNBytesBounded(8 * 1024 * 1024) }
            QrDecoder.decodeBytes(bytes)
        }

    fun enroll(raw: String, complete: (Boolean, String) -> Unit) =
        operation("Setup could not finish. Your existing account was preserved; check the setup message.", complete) {
            check(runtime!!.callAttr("enroll", raw).toBoolean())
            "Account activated. Finish the verification sign-in."
        }

    fun resumeSetup(complete: (Boolean, String) -> Unit) =
        operation("Saved setup is not ready. Scan a fresh setup QR code.", complete) {
            runtime!!.callAttr("resume_setup")
            "Setup resumed. Finish the verification sign-in."
        }

    fun importSetup(uri: Uri, password: String, complete: (Boolean, String) -> Unit) =
        operation("Could not import the backup. Check the password and file; the current account was preserved.", complete) {
            val archive = temporary(".zip")
            try {
                copyInput(uri, archive, BackupCrypto.maxArchive)
                val bytes = archive.readBytes()
                if (BackupCrypto.isEncrypted(bytes)) {
                    val plaintext = BackupCrypto.decrypt(bytes, password)
                    try { archive.writeBytes(plaintext) } finally { plaintext.fill(0) }
                }
                runtime!!.callAttr("import_setup", archive.absolutePath)
                "Setup imported."
            } finally { archive.delete() }
        }

    fun exportSetup(uri: Uri, password: String, complete: (Boolean, String) -> Unit) =
        operation("Could not export the backup. Disconnect and try again.", complete) {
            val archive = temporary(".zip")
            // Python exports exclusively into a new file.
            archive.delete()
            try {
                runtime!!.callAttr("export_setup", archive.absolutePath)
                val plain = archive.readBytes()
                val backup = try { BackupCrypto.encode(plain, password) } finally { plain.fill(0) }
                try {
                    app.contentResolver.openOutputStream(uri, "wt").use { output ->
                        requireNotNull(output).write(backup)
                    }
                } finally { backup.fill(0) }
                if (password.isEmpty()) "Backup saved without a password."
                else "Encrypted backup saved. Keep its password for restoring."
            } finally { archive.delete() }
        }
}
