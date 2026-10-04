package io.github.infarctus.nodauth

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONArray
import java.security.MessageDigest

object ApkIdentity {
    @Suppress("DEPRECATION")
    fun fingerprints(context: Context, path: String): String {
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        val info = context.packageManager.getPackageArchiveInfo(path, flags) ?: error("Unsupported APK")
        require(info.packageName == "com.azure.authenticator")
        val signers = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
        require(!signers.isNullOrEmpty())
        val hashes = signers.map { signature ->
            MessageDigest.getInstance("SHA-1").digest(signature.toByteArray())
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }
        return JSONArray(hashes).toString()
    }
}
