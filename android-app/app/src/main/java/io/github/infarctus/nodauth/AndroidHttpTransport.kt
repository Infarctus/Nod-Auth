package io.github.infarctus.nodauth

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/** Use Android's native TLS, without redirects or automatic activation retries. */
object AndroidHttpTransport {
    private val client = OkHttpClient.Builder()
        .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
        .connectTimeout(30, TimeUnit.SECONDS).build()

    @JvmStatic
    fun post(url: String, body: String, action: String, userAgent: String, timeout: Int): String {
        require(timeout in 1..120 && body.length <= 2 * 1024 * 1024)
        val request = Request.Builder().url(url)
            .header("SOAPAction", action).header("User-Agent", userAgent)
            .post(body.toRequestBody("text/xml; charset=utf-8".toMediaType())).build()
        require(request.url.isHttps)
        val session = client.newBuilder().readTimeout(timeout.toLong(), TimeUnit.SECONDS)
            .callTimeout(timeout.toLong(), TimeUnit.SECONDS).build()
        session.newCall(request).execute().use { response ->
            val bytes = response.body?.byteStream()?.use { it.readNBytesBounded(2 * 1024 * 1024) } ?: byteArrayOf()
            return JSONObject().put("status", response.code).put("text", bytes.toString(Charsets.UTF_8)).toString()
        }
    }

    @JvmStatic
    fun googlePost(url: String, data: String, headers: String): String {
        val values = JSONObject(headers)
        val bytes = android.util.Base64.decode(data, android.util.Base64.NO_WRAP)
        require(bytes.size <= 2 * 1024 * 1024)
        val builder = Request.Builder().url(url)
            .post(bytes.toRequestBody(values.optString("Content-Type", "application/octet-stream").toMediaType()))
        for (name in values.keys()) builder.header(name, values.getString(name))
        val request = builder.build()
        require(request.url.isHttps && request.url.host in setOf("android.clients.google.com", "firebaseinstallations.googleapis.com", "fcmtoken.googleapis.com"))
        client.newBuilder().readTimeout(30, TimeUnit.SECONDS).callTimeout(30, TimeUnit.SECONDS)
            .build().newCall(request).execute().use { response ->
                val body = response.body?.byteStream()?.use { it.readNBytesBounded(2 * 1024 * 1024) } ?: byteArrayOf()
                return JSONObject().put("status", response.code)
                    .put("body", android.util.Base64.encodeToString(body, android.util.Base64.NO_WRAP)).toString()
            }
    }

    @JvmStatic
    fun publicCheck(): Int {
        val request = Request.Builder().url("https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration").build()
        client.newBuilder().callTimeout(20, TimeUnit.SECONDS).build().newCall(request).execute().use { return it.code }
    }
}

internal fun java.io.InputStream.readNBytesBounded(limit: Int): ByteArray {
    val output = java.io.ByteArrayOutputStream()
    val buffer = ByteArray(8192)
    while (true) {
        val count = read(buffer)
        if (count < 0) break
        require(output.size() + count <= limit)
        output.write(buffer, 0, count)
    }
    return output.toByteArray()
}
