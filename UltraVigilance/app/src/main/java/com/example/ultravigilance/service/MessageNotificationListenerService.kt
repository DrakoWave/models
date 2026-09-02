package com.example.ultravigilance.service

import android.app.Notification
import android.os.Bundle
import android.provider.Telephony
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.example.ultravigilance.receiver.SmsScanReceiver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Real-time Notification Listener Service.
 *
 * Exclusively intercepts incoming SMS (cellular) and RCS messages from dedicated SMS/RCS applications.
 * Sends the content to the live AI backend and raises instant fraud notifications when threats are detected.
 */
class MessageNotificationListenerService : NotificationListenerService() {

    companion object {
        private const val TAG = "MessageNotifListener"

        // Dedicated SMS & RCS telephony client packages across Android OEMs
        private val KNOWN_SMS_RCS_PACKAGES = setOf(
            "com.google.android.apps.messaging", // Google Messages (Primary SMS + RCS)
            "com.samsung.android.messaging",     // Samsung Messages (SMS + RCS)
            "com.android.mms",                    // Standard AOSP Messaging
            "com.oneplus.mms",                    // OnePlus Messaging
            "com.xiaomi.mms",                     // Xiaomi Messaging
            "com.miui.mms",                       // MIUI Messaging
            "com.oppo.mms",                       // Oppo Messaging
            "com.heytap.mms",                     // Realme / ColorOS Messaging
            "com.vivo.mms",                       // Vivo Messaging
            "com.sonyericsson.conversations",     // Sony Xperia Messaging
            "com.motorola.messaging"              // Motorola Messaging
        )

        // Maps message content -> Pair(SenderName, Timestamp) to prevent duplicate alerts
        private val recentMessageCache = LinkedHashMap<String, Pair<String, Long>>()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName ?: return

        // 1. Never intercept our own app's alert notifications (prevents infinite loop)
        if (packageName == applicationContext.packageName) return

        // 2. Strict Filter: Only accept notifications from the default SMS app or known SMS/RCS packages
        val defaultSmsPackage = try {
            Telephony.Sms.getDefaultSmsPackage(this)
        } catch (e: Exception) {
            null
        }

        val isSmsOrRcsApp = (defaultSmsPackage != null && packageName == defaultSmsPackage) ||
                KNOWN_SMS_RCS_PACKAGES.contains(packageName)

        if (!isSmsOrRcsApp) {
            // Strictly ignore all non-SMS/non-RCS applications
            return
        }

        val notification = sbn.notification ?: return
        val extras: Bundle = notification.extras ?: return

        // 3. Extract sender and message text
        var senderTitle = extras.getCharSequence(Notification.EXTRA_CONVERSATION_TITLE)?.toString()
            ?: extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
            ?: ""

        val messageText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            ?: extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
            ?: ""

        if (messageText.isBlank()) return

        // Ignore generic placeholder titles like "Messages" or "New message" if possible
        if (senderTitle.isBlank() || senderTitle.equals("Messages", ignoreCase = true) || senderTitle.equals("Google Messages", ignoreCase = true)) {
            senderTitle = "Unknown Sender"
        }

        val normalizedMessage = messageText.trim()
        val now = System.currentTimeMillis()

        // 4. Deduplicate on message text: Ensure ONLY ONE alert per message
        synchronized(recentMessageCache) {
            val cachedEntry = recentMessageCache[normalizedMessage]
            if (cachedEntry != null) {
                val (cachedSender, timestamp) = cachedEntry
                val hasBetterSender = (cachedSender == "Unknown Sender" && senderTitle != "Unknown Sender")
                val isRecent = (now - timestamp < 15_000)

                if (isRecent && !hasBetterSender) {
                    return // Already processed and sender hasn't improved -> ignore to prevent duplicate notifications
                }
            }

            recentMessageCache[normalizedMessage] = Pair(senderTitle, now)
            if (recentMessageCache.size > 50) {
                val oldestKey = recentMessageCache.keys.first()
                recentMessageCache.remove(oldestKey)
            }
        }

        Log.d(TAG, "Intercepted SMS/RCS from $senderTitle: $normalizedMessage. Initiating live backend scan...")

        // 5. Query live FastAPI backend asynchronously
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val verdict = SmsScanReceiver.scanMessage(senderTitle, normalizedMessage)
                Log.d(TAG, "Backend verdict for $senderTitle: ${verdict.verdict}")

                // 6. Raise instant heads-up fraud alert if marked as FRAUD or SUSPICIOUS
                if (verdict.verdict == "FRAUD" || verdict.verdict == "SUSPICIOUS") {
                    SmsScanReceiver.showAlertNotification(
                        context = applicationContext,
                        sender = senderTitle,
                        body = normalizedMessage,
                        verdict = verdict
                    )
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error in live scan notification handler", e)
            }
        }
    }
}
