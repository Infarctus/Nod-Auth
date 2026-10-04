package io.github.infarctus.nodauth

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper

/** A user-started, ten-minute connection, including when switching to a browser. */
class ListenerService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    private val controller get() = (application as NodAuthApplication).controller
    private var previousRequest = ""
    private var sawListening = false
    private var setupSession = false
    private var startedAt = 0L
    private val timeout = Runnable { stopSelf() }
    private val monitor = object : Runnable {
        override fun run() {
            val state = controller.state
            val active = state.optBoolean("listening") || state.optBoolean("enrolling") || controller.busy
            if (active) sawListening = true
            if (!active && (sawListening ||
                    controller.ready && android.os.SystemClock.elapsedRealtime() - startedAt > 3000)) {
                stopSelf(); return
            }
            val id = state.optJSONObject("request")?.optString("id") ?: ""
            if (id != previousRequest) {
                previousRequest = id
                getSystemService(NotificationManager::class.java).notify(1, notification(id.isNotEmpty()))
            }
            handler.postDelayed(this, 500)
        }
    }

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel("session", "Nod Auth sign-in session", NotificationManager.IMPORTANCE_DEFAULT)
                    .apply { lockscreenVisibility = Notification.VISIBILITY_PRIVATE }
            )
        }
    }

    private fun notification(request: Boolean): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, ListenerService::class.java)
            .setAction("STOP"), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, "session") else Notification.Builder(this)
        return builder.setSmallIcon(R.drawable.ic_authenticator)
            .setContentTitle(if (controller.state.optBoolean("enrolling") || setupSession) "Setting up your account" else if (request) "Sign-in request received" else "${getString(R.string.app_name)} is listening")
            .setContentText(if (setupSession) "Return to the app to follow setup." else if (request) "Open the app to review it." else "This session ends after ten minutes.")
            .setContentIntent(open).setOngoing(true).setVisibility(Notification.VISIBILITY_PRIVATE)
            .apply { if (!setupSession) addAction(Notification.Action.Builder(null, "Disconnect", stop).build()) }
            .build()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") { stopSelf(); return START_NOT_STICKY }
        setupSession = intent?.action == "SETUP"
        startForeground(1, notification(false))
        startedAt = android.os.SystemClock.elapsedRealtime()
        sawListening = false
        if (!setupSession) controller.start()
        handler.removeCallbacks(timeout)
        handler.postDelayed(timeout, 10 * 60 * 1000L)
        handler.removeCallbacks(monitor)
        handler.post(monitor)
        return START_NOT_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) { stopSelf() }
    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        controller.stop()
        super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null
}
