package io.github.infarctus.nodauth

import android.Manifest
import android.app.KeyguardManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.json.JSONObject

private val Green = Color(0xFF176B5B)
private val Ink = Color(0xFF142A26)
private val Red = Color(0xFFBA2938)

class MainActivity : FragmentActivity() {
    private val controller get() = (application as NodAuthApplication).controller
    private var pendingCredential: (() -> Unit)? = null
    private var returningFromPicker = false
    private var manuallyDisconnected = false
    private var setupVisible by mutableStateOf(false)
    private var scannedQr by mutableStateOf<String?>(null)
    private var qrHost by mutableStateOf("")
    private var importUri by mutableStateOf<Uri?>(null)
    private var exportPassword: String? = null
    private val credentials = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val pending = pendingCredential
        pendingCredential = null
        if (result.resultCode == RESULT_OK) pending?.invoke()
    }
    private val notifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }
    private val picker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> importUri = uri }
    private val apkPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) controller.prepareApk(uri) { _, message -> toast(message) }
    }
    private val imagePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) controller.readQrImage(uri) { success, text -> if (success) inspectQr(text) else toast(text) }
    }
    private val scanner = registerForActivityResult(ScanContract()) { result -> result.contents?.let { inspectQr(it) } }
    private val exportPicker = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val password = exportPassword
        exportPassword = null
        if (uri != null && password != null) controller.exportSetup(uri, password) { _, message -> toast(message) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        manuallyDisconnected = savedInstanceState?.getBoolean("manuallyDisconnected") ?: false
        setupVisible = savedInstanceState?.getBoolean("setupVisible") ?: false
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            MaterialTheme(colorScheme = lightColorScheme(primary = Green, onPrimary = Color.White,
                background = Color(0xFFF5F8F6), surface = Color.White, onBackground = Ink, onSurface = Ink)) {
                var diagnostics by remember { mutableStateOf(false) }
                var confirmImport by remember { mutableStateOf(false) }
                var confirmActivation by remember { mutableStateOf(false) }
                var resumeActivation by remember { mutableStateOf(false) }
                var backupDialog by remember { mutableStateOf(false) }
                var attemptedAutoStart by rememberSaveable { mutableStateOf(false) }
                val state = controller.state
                val hasSetup = state.optBoolean("has_setup")
                val idle = controller.ready && !controller.busy && !state.optBoolean("listening")
                LaunchedEffect(controller.ready) {
                    if (controller.ready && !attemptedAutoStart) {
                        attemptedAutoStart = true
                        if (hasSetup && !setupVisible && !manuallyDisconnected) connect()
                    }
                }
                val request = state.optJSONObject("request")
                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp)) {
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Text(stringResource(R.string.app_name), fontSize = 26.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                            Box(Modifier.size(10.dp).background(if (state.optBoolean("connected")) Green else Color(0xFF9DAAA6), RoundedCornerShape(5.dp)))
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(state.optString("status", "Starting…"), color = Green, fontSize = 14.sp)
                        if (request != null) {
                            ApprovalScreen(request, Modifier.weight(1f)) { value -> respond(request, value) }
                        } else if (setupVisible) {
                            Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                                Spacer(Modifier.height(8.dp))
                                Text("Set up on this phone", fontSize = 28.sp, fontWeight = FontWeight.Bold)
                                Text("1. Download the original Microsoft Authenticator APK, then select it here. You only need to do this once.")
                                OutlinedButton(onClick = { returningFromPicker = true; apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }, enabled = idle, modifier = Modifier.fillMaxWidth()) { Text("Choose Authenticator APK") }
                                if (state.optBoolean("apk_ready")) Text("APK configuration ready · ${state.optString("apk_version")}", color = Green)
                                Text("2. Add an Authenticator app in your Microsoft work or school security settings. Scan its fresh QR code.")
                                Button(onClick = { scan() }, enabled = idle && state.optBoolean("apk_ready"), modifier = Modifier.fillMaxWidth()) { Text("Scan setup QR code") }
                                OutlinedButton(onClick = { returningFromPicker = true; imagePicker.launch(arrayOf("image/*")) }, enabled = idle && state.optBoolean("apk_ready"), modifier = Modifier.fillMaxWidth()) { Text("Choose QR image") }
                                if (scannedQr != null) Text("Microsoft MFA setup code ready · $qrHost", color = Green)
                                Text("3. Activate, then finish the verification sign-in. Setup runs here; no computer enrollment is needed.")
                                Button(onClick = { resumeActivation = false; if (hasSetup) confirmActivation = true else activateScanned() }, enabled = idle && scannedQr != null && state.optBoolean("apk_ready"), modifier = Modifier.fillMaxWidth()) { Text("Activate account") }
                                if (state.optBoolean("draft_ready")) OutlinedButton(onClick = { resumeActivation = true; if (hasSetup) confirmActivation = true else resumeSetup() }, enabled = idle, modifier = Modifier.fillMaxWidth()) { Text("Resume activated setup") }
                                if (controller.busy) CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
                                Text(state.optString("message"), lineHeight = 23.sp)
                            }
                            TextButton(onClick = { setupVisible = false; scannedQr = null; qrHost = "" }, enabled = !controller.busy) { Text("Back") }
                        } else {
                            Column(Modifier.weight(1f).fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                                Text(if (hasSetup) "Ready when you are" else "Add your account", fontSize = 30.sp, fontWeight = FontWeight.Bold)
                                Spacer(Modifier.height(16.dp))
                                Text(if (hasSetup) "Connect first, then start a Microsoft sign-in. Your request will appear here."
                                    else "Set up directly on this phone with the Authenticator APK and a Microsoft setup QR code, or import a backup.", textAlign = TextAlign.Center, color = Color(0xFF5C706A), lineHeight = 24.sp)
                                Spacer(Modifier.height(24.dp))
                                if (controller.busy) CircularProgressIndicator()
                                Text(state.optString("message"), textAlign = TextAlign.Center, color = Ink)
                            }
                            if (hasSetup) Button(onClick = { if (state.optBoolean("listening")) disconnect() else connect() }, modifier = Modifier.fillMaxWidth(), enabled = controller.ready && !controller.busy) { Text(if (state.optBoolean("listening")) "Disconnect" else "Connect for 10 minutes") }
                            OutlinedButton(onClick = { setupVisible = true }, enabled = idle, modifier = Modifier.fillMaxWidth()) { Text("Set up with QR code") }
                            OutlinedButton(onClick = { if (hasSetup) confirmImport = true else chooseSetup() }, enabled = idle, modifier = Modifier.fillMaxWidth()) { Text("Import backup / setup ZIP") }
                            if (hasSetup) OutlinedButton(onClick = { backupDialog = true }, enabled = idle, modifier = Modifier.fillMaxWidth()) { Text("Export backup") }
                            if (state.optBoolean("listening")) Text("Disconnect to manage setup or backups.", fontSize = 12.sp, color = Color(0xFF5C706A))
                            TextButton(onClick = { diagnostics = !diagnostics }, modifier = Modifier.align(Alignment.End)) { Text("Runtime check") }
                        }
                        if (diagnostics) Text(state.optString("diagnostics").ifEmpty { "Checking Python and Microsoft TLS…" }, fontSize = 12.sp, color = Color(0xFF5C706A))
                    }
                }
                if (confirmImport) AlertDialog(onDismissRequest = { confirmImport = false }, title = { Text("Replace this setup?") }, text = { Text("The imported backup will replace this phone's enrollment after validation.") },
                    confirmButton = { TextButton(onClick = { confirmImport = false; chooseSetup() }) { Text("Choose backup") } }, dismissButton = { TextButton(onClick = { confirmImport = false }) { Text("Cancel") } })
                if (confirmActivation) AlertDialog(onDismissRequest = { confirmActivation = false }, title = { Text("Replace this account?") }, text = { Text("Your current setup stays intact until the new activation completes. Then verify the new setup with a sign-in.") },
                    confirmButton = { TextButton(onClick = { confirmActivation = false; if (resumeActivation) resumeSetup() else activateScanned() }) { Text("Continue") } }, dismissButton = { TextButton(onClick = { confirmActivation = false }) { Text("Cancel") } })
                val selectedImport = importUri
                if (selectedImport != null) PasswordDialog("Import backup", "Enter the backup password, or leave it blank if the backup has no password.", false, onDismiss = { importUri = null }) { password ->
                    importUri = null
                    controller.importSetup(selectedImport, password) { success, message -> finishSetup(success, message) }
                }
                if (backupDialog) PasswordDialog("Export backup", "Add a password to encrypt the backup, or leave it blank to save without a password.", true, onDismiss = { backupDialog = false }) { password ->
                    backupDialog = false
                    unlock("Export backup") {
                        exportPassword = password
                        returningFromPicker = true
                        exportPicker.launch(if (password.isEmpty()) "nod-auth-backup.zip" else "nod-auth-backup.nodbackup")
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (returningFromPicker) { returningFromPicker = false; return }
        if (!setupVisible && importUri == null && !manuallyDisconnected && controller.ready && controller.state.optBoolean("has_setup") && !controller.state.optBoolean("listening") && !controller.busy) connect()
    }
    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean("manuallyDisconnected", manuallyDisconnected)
        outState.putBoolean("setupVisible", setupVisible)
        super.onSaveInstanceState(outState)
    }
    private fun toast(message: String) { Toast.makeText(this, message, Toast.LENGTH_LONG).show() }
    private fun inspectQr(raw: String) {
        controller.inspectQr(raw) { success, result ->
            if (success) { scannedQr = raw; qrHost = result }
            else { scannedQr = null; qrHost = ""; toast(result) }
        }
    }
    private fun scan() {
        scannedQr = null
        qrHost = ""
        returningFromPicker = true
        scanner.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("Scan your Microsoft work or school setup QR code")
            .setBeepEnabled(false).setBarcodeImageEnabled(false).setOrientationLocked(false).setCaptureActivity(QrCaptureActivity::class.java))
    }
    private fun activateScanned() {
        val raw = scannedQr ?: return
        scannedQr = null
        qrHost = ""
        requestNotifications()
        val service = Intent(this, ListenerService::class.java).setAction("SETUP")
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(service) else startService(service)
        controller.enroll(raw) { success, message -> finishSetup(success, message) }
    }
    private fun resumeSetup() { controller.resumeSetup { success, message -> finishSetup(success, message) } }
    private fun finishSetup(success: Boolean, message: String) {
        toast(message)
        if (success) {
            setupVisible = false
            manuallyDisconnected = false
            if (lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) { connect(); return }
        }
        stopService(Intent(this, ListenerService::class.java))
    }
    private fun chooseSetup() { returningFromPicker = true; picker.launch(arrayOf("application/zip", "application/octet-stream")) }
    private fun requestNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
    private fun connect() {
        manuallyDisconnected = false
        requestNotifications()
        val service = Intent(this, ListenerService::class.java)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(service) else startService(service)
    }
    private fun disconnect() { manuallyDisconnected = true; stopService(Intent(this, ListenerService::class.java)) }
    private fun respond(request: JSONObject, value: String) {
        val id = request.getString("id")
        if (value == "DENY" || !request.optBoolean("lock_required")) controller.answer(id, value, false)
        else unlock("Confirm sign-in") { controller.answer(id, value, true) }
    }
    private fun unlock(title: String, success: () -> Unit) {
        if (Build.VERSION.SDK_INT < 30) {
            val intent = getSystemService(KeyguardManager::class.java).createConfirmDeviceCredentialIntent(title, "Unlock to continue")
            if (intent != null) { pendingCredential = success; returningFromPicker = true; credentials.launch(intent) } else toast("Set a device screen lock before continuing.")
            return
        }
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (BiometricManager.from(this).canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) { toast("Set a device screen lock or biometric before continuing."); return }
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { success() }
        })
        prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(title).setSubtitle("Unlock to continue").setAllowedAuthenticators(authenticators).build())
    }
}

@Composable
private fun PasswordDialog(title: String, description: String, exporting: Boolean, onDismiss: () -> Unit, submit: (String) -> Unit) {
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    AlertDialog(onDismissRequest = onDismiss, title = { Text(title) }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(description)
            OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text(if (exporting) "Password (optional)" else "Password") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), visualTransformation = PasswordVisualTransformation())
            if (exporting && password.isNotEmpty()) OutlinedTextField(value = confirm, onValueChange = { confirm = it }, label = { Text("Confirm password") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), visualTransformation = PasswordVisualTransformation())
        }
    }, confirmButton = { TextButton(onClick = { val value = password; password = ""; confirm = ""; submit(value) }, enabled = !exporting || password.isEmpty() || password == confirm) { Text(if (exporting) "Choose save location" else "Import") } }, dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}

@Composable
private fun ApprovalScreen(request: JSONObject, modifier: Modifier, respond: (String) -> Unit) {
    Column(modifier.fillMaxWidth()) {
        Column(Modifier.weight(1f).fillMaxWidth(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Is this your sign-in?", fontSize = 30.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
            Spacer(Modifier.height(14.dp))
            Text(request.optString("details"), textAlign = TextAlign.Center, color = Color(0xFF5C706A), fontSize = 14.sp)
            Spacer(Modifier.height(24.dp))
            val choices = request.getJSONArray("choices")
            val numbered = choices.length() == 3
            Text(if (numbered) "Tap the number shown on your sign-in page" else "Approve only if you started this request", textAlign = TextAlign.Center, lineHeight = 24.sp)
            Spacer(Modifier.height(32.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                for (index in 0 until choices.length()) {
                    val number = choices.getString(index)
                    Button(onClick = { respond(number) }, modifier = Modifier.weight(1f).height(84.dp), shape = RoundedCornerShape(20.dp), contentPadding = PaddingValues(0.dp)) {
                        Text(if (number == "APPROVE") "Approve" else number, fontSize = if (numbered) 32.sp else 22.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
            Text("Expires in ${request.optInt("seconds")}s", color = Color(0xFF5C706A), fontSize = 13.sp)
        }
        Row(Modifier.fillMaxWidth().padding(bottom = 24.dp), horizontalArrangement = Arrangement.End) {
            Button(onClick = { respond("DENY") }, colors = ButtonDefaults.buttonColors(containerColor = Red), shape = RoundedCornerShape(16.dp), modifier = Modifier.height(52.dp)) { Text("Deny", fontWeight = FontWeight.Bold) }
        }
    }
}
