package com.yuceyang.gatepassandroid.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import com.yuceyang.gatepassandroid.data.SecureSettingsStore
import com.yuceyang.gatepassandroid.diag.DiagLog
import com.yuceyang.gatepassandroid.proxy.CertificateAuthority
import com.yuceyang.gatepassandroid.proxy.LocalHttpIngress
import com.yuceyang.gatepassandroid.proxy.Socks5ProxyServer
import com.yuceyang.gatepassandroid.ui.MainActivity
import hev.htproxy.TProxyService
import java.io.File
import java.net.DatagramSocket
import java.net.Socket

class GatePassVpnService : VpnService() {
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var socksServer: Socks5ProxyServer? = null
    @Volatile private var httpIngress: LocalHttpIngress? = null
    @Volatile private var nativeTunnelStarted = false
    @Volatile private var wakeLock: PowerManager.WakeLock? = null
    @Volatile private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var activeNetwork: Network? = null
    private val housekeeping = Handler(Looper.getMainLooper())
    private val housekeepingTask = object : Runnable {
        override fun run() {
            httpIngress?.evictIdleUpstreams()
            if (running()) {
                applyAdaptiveWakeLock()
                housekeeping.postDelayed(this, HOUSEKEEPING_INTERVAL_MS)
            }
        }
    }

    /**
     * Holding a wake lock while idle burns battery for nothing. Keep it only while traffic is
     * recent (or while the user just started the tunnel), and let the device sleep otherwise;
     * the foreground service still receives new requests and re-acquires on demand.
     */
    private fun applyAdaptiveWakeLock() {
        val idleMs = httpIngress?.idleForMs() ?: Long.MAX_VALUE
        val recentlyActive = idleMs < IDLE_WAKE_LOCK_GRACE_MS
        if (recentlyActive && wakeLock?.isHeld != true) {
            acquireWakeLock()
            DiagLog.log("有流量，恢复 CPU 唤醒锁")
        } else if (!recentlyActive && wakeLock?.isHeld == true) {
            releaseWakeLock()
            DiagLog.log("空闲 ${idleMs / 1000}s，释放 CPU 唤醒锁省电")
        }
    }

    private fun running() = tun != null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                DiagLog.log("收到停止指令")
                stopVpn()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf(startId)
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (tun != null) return
        createNotificationChannel()
        startForegroundCompat(buildNotification())
        DiagLog.log("VPN 启动请求")
        try {
            val store = SecureSettingsStore(this)
            val routes = store.loadRoutes()
            DiagLog.log("已配置路由 ${routes.size} 条${if (routes.isEmpty()) "（无路由，仅 DNS 透传）" else ": " + routes.joinToString()}")
            val underlyingNetwork = getSystemService(ConnectivityManager::class.java).activeNetwork
            activeNetwork = underlyingNetwork
            acquireWakeLock()
            val socks = Socks5ProxyServer(
                store = store,
                ca = CertificateAuthority(this),
                protectSocket = { protect(it) },
                protectDatagram = { protect(it) },
                underlyingNetwork = underlyingNetwork,
            )
            socks.start()
            socksServer = socks

            LocalHttpIngress(store, underlyingNetwork).also {
                httpIngress = it
                it.start()
            }

            val builder = Builder()
                .setSession("GatePass Android")
                .setMtu(TUN_MTU)
                .addAddress(TUN_ADDRESS, 32)
                .addDnsServer(MAP_DNS_ADDRESS)
                .addRoute(MAP_DNS_ADDRESS, 32)
                .addRoute(MAPPED_IPV4_NETWORK, MAPPED_IPV4_PREFIX)
            val descriptor = builder.establish() ?: throw IllegalStateException("Android did not establish the VPN interface")
            tun = descriptor
            if (underlyingNetwork != null) setUnderlyingNetworks(arrayOf(underlyingNetwork))
            DiagLog.log("TUN 已建立，底层网络=${underlyingNetwork?.toString() ?: "未知"}")

            val configFile = File(filesDir, HEV_CONFIG_FILE)
            configFile.writeText(hevConfig(), Charsets.UTF_8)
            if (!TProxyService.TProxyStartService(configFile.absolutePath, descriptor.fd)) {
                throw IllegalStateException("HEV TUN-to-SOCKS5 service failed to start")
            }
            nativeTunnelStarted = true
            isRunning = true
            DiagLog.log("HEV tun2socks 已启动")
            registerNetworkCallback()
            housekeeping.postDelayed(housekeepingTask, HOUSEKEEPING_INTERVAL_MS)
            updateNotification("VPN 已连接 · 系统 DNS 域名路由已启用")
        } catch (error: Exception) {
            DiagLog.error("VPN 启动失败", error)
            updateNotification("VPN 启动失败：${error.message ?: "未知错误"}")
            stopVpn()
            stopSelf()
        }
    }

    private fun hevConfig() = """
        tunnel:
          mtu: $TUN_MTU
          ipv4:
            address: $TUN_ADDRESS
        socks5:
          address: 127.0.0.1
          port: ${Socks5ProxyServer.DEFAULT_PORT}
          udp: udp
        mapdns:
          address: $MAP_DNS_ADDRESS
          port: 53
          network: $MAPPED_IPV4_NETWORK
          netmask: $MAPPED_IPV4_NETMASK
          cache-size: 8192
        misc:
          log-level: warn
    """.trimIndent()

    private fun stopVpn() {
        housekeeping.removeCallbacks(housekeepingTask)
        unregisterNetworkCallback()
        releaseWakeLock()
        if (nativeTunnelStarted) {
            runCatching { TProxyService.TProxyStopService() }
            nativeTunnelStarted = false
            DiagLog.log("HEV tun2socks 已停止")
        }
        socksServer?.close()
        socksServer = null
        httpIngress?.close()
        httpIngress = null
        runCatching { tun?.close() }
        tun = null
        // Detach from the underlying network so Android drops the VPN route/DNS immediately.
        runCatching { setUnderlyingNetworks(null) }
        activeNetwork = null
        isRunning = false
        DiagLog.log("VPN 已断开")
    }

    /**
     * Keeps the CPU alive while traffic is recent. Without this, Doze suspends the process and
     * background sync stalls until the next wakeup. [applyAdaptiveWakeLock] releases it again
     * once the tunnel has been idle, and [stopVpn] always releases it.
     */
    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        runCatching {
            val manager = getSystemService(PowerManager::class.java)
            wakeLock = manager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "$packageName:gatepass-vpn").apply {
                setReferenceCounted(false)
                acquire(WAKE_LOCK_TIMEOUT_MS)
            }
            DiagLog.log("已获取 CPU 唤醒锁")
        }.onFailure { DiagLog.error("获取唤醒锁失败", it) }
    }

    private fun releaseWakeLock() {
        runCatching { wakeLock?.takeIf { it.isHeld }?.release() }
        wakeLock = null
    }

    /**
     * Re-points the tunnel at the new default network after Wi-Fi/cellular handover; otherwise
     * protected sockets keep trying to leave through an interface that no longer has a route.
     */
    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val manager = getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (activeNetwork == network) return
                activeNetwork = network
                runCatching { setUnderlyingNetworks(arrayOf(network)) }
                DiagLog.log("底层网络切换 → ${network}")
                httpIngress?.evictIdleUpstreams()
            }

            override fun onLost(network: Network) {
                if (activeNetwork == network) DiagLog.log("底层网络断开 ${network}")
            }
        }
        runCatching {
            manager.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        }.onFailure { DiagLog.error("注册网络回调失败", it) }
    }

    private fun unregisterNetworkCallback() {
        val callback = networkCallback ?: return
        networkCallback = null
        runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback) }
    }

    private fun buildNotification(text: String = "等待 VPN 启动") = Notification.Builder(this, CHANNEL_ID)
        .setContentTitle("GatePass Android")
        .setContentText(text)
        .setSmallIcon(android.R.drawable.stat_sys_warning)
        .setOngoing(true)
        .setContentIntent(
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            ),
        )
        .addAction(
            android.R.drawable.ic_menu_close_clear_cancel,
            "停止",
            PendingIntent.getService(
                this,
                1,
                Intent(this, GatePassVpnService::class.java).setAction(ACTION_STOP),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            ),
        )
        .build()

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "GatePass VPN", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    override fun onRevoke() {
        stopVpn()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    companion object {
        /** True while the tunnel is established; the UI reads it to show connection state. */
        @Volatile var isRunning: Boolean = false
            private set

        const val ACTION_START = "com.yuceyang.gatepassandroid.vpn.START"
        const val ACTION_STOP = "com.yuceyang.gatepassandroid.vpn.STOP"
        private const val CHANNEL_ID = "gatepass_vpn"
        private const val NOTIFICATION_ID = 7104
        private const val HOUSEKEEPING_INTERVAL_MS = 60_000L
        /** Keep the CPU awake for this long after the last proxied request. */
        private const val IDLE_WAKE_LOCK_GRACE_MS = 3 * 60_000L
        // Bounded so a leaked service can never pin the CPU forever; renewed by each start.
        private const val WAKE_LOCK_TIMEOUT_MS = 12L * 60 * 60 * 1000
        private const val TUN_MTU = 1500
        private const val TUN_ADDRESS = "10.79.0.1"
        private const val MAP_DNS_ADDRESS = "10.79.0.2"
        // Deliberately away from Clash's default fake-ip range (198.18.0.1/16) so the two VPNs
        // can run side by side without interpreting the same virtual address as different hosts.
        private const val MAPPED_IPV4_NETWORK = "198.19.0.0"
        private const val MAPPED_IPV4_NETMASK = "255.255.0.0"
        private const val MAPPED_IPV4_PREFIX = 16
        private const val HEV_CONFIG_FILE = "hev-socks5-tunnel.yml"
    }
}
