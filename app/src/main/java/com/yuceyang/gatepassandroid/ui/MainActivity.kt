package com.yuceyang.gatepassandroid.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.yuceyang.gatepassandroid.auth.UgosAuthClient
import com.yuceyang.gatepassandroid.data.PortableConfig
import com.yuceyang.gatepassandroid.data.ProxyRoute
import com.yuceyang.gatepassandroid.data.SecureSettingsStore
import com.yuceyang.gatepassandroid.diag.DiagLog
import com.yuceyang.gatepassandroid.proxy.CertificateAuthority
import com.yuceyang.gatepassandroid.proxy.LocalHttpIngress
import com.yuceyang.gatepassandroid.vpn.GatePassVpnService

class MainActivity : androidx.activity.ComponentActivity() {
    private lateinit var store: SecureSettingsStore
    private lateinit var aliasField: EditText
    private lateinit var suffixField: EditText
    private lateinit var username: EditText
    private lateinit var password: EditText
    private lateinit var routePort: EditText
    private lateinit var routeHost: EditText
    private lateinit var routeSystem: android.widget.CheckBox
    private lateinit var status: TextView
    private lateinit var logView: TextView
    private lateinit var loginButton: Button
    private lateinit var loginStateView: TextView
    private lateinit var routeList: LinearLayout
    private lateinit var vpnState: TextView
    private lateinit var startVpnButton: Button
    private lateinit var stopVpnButton: Button
    private lateinit var caState: TextView
    /** Set when we leave for the certificate screen so we can restore the tunnel on return. */
    private var resumeVpnAfterSettings = false
    /** Remembers whether the pending export should include the password. */
    private var pendingExportIncludePassword = true

    private val vpnLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            showStatus("未授予 VPN 权限")
        }
    }

    private val exportLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.CreateDocument("application/json"),
    ) { uri -> if (uri != null) writePortable(uri, pendingExportIncludePassword) }

    private val importLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.OpenDocument(),
    ) { uri -> if (uri != null) readPortable(uri) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = SecureSettingsStore(this)
        buildUi()
        restoreFields()
        refreshLoginState()
        DiagLog.addListener(::refreshLog)
        refreshLog()
        refreshVpnState()
    }

    override fun onResume() {
        super.onResume()
        refreshVpnState()
        refreshCaState()
        refreshLoginState()
        // Opening Settings (e.g. to install the CA) tears the VPN down on some OEM builds.
        // Restore it automatically so the user does not have to start it again.
        if (resumeVpnAfterSettings) {
            resumeVpnAfterSettings = false
            if (!GatePassVpnService.isRunning && store.loadRoutes().isNotEmpty()) {
                DiagLog.log("从系统设置返回，自动恢复 VPN")
                startVpnService()
            }
        }
    }

    override fun onDestroy() {
        DiagLog.removeListener(::refreshLog)
        super.onDestroy()
    }

    private fun refreshLog() {
        if (!::logView.isInitialized) return
        runOnUiThread { logView.text = DiagLog.snapshot().ifBlank { "（暂无日志）" } }
    }

    // ---------------------------------------------------------------- layout

    private fun buildUi() {
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(28))
            setBackgroundColor(COLOR_BG)
        }
        page.addView(buildHeader(), matchWidth())

        page.addView(card("NAS 登录", "只需填 UGREENlink 别名和账号。GatePass 会自动向绿联查询设备当前的访问地址。") {
            aliasField = input("UGREENlink 别名", "yuceyang", InputType.TYPE_TEXT_VARIATION_URI)
            username = input("用户名", "NAS 登录账号")
            password = input("密码", "NAS 登录密码", InputType.TYPE_TEXT_VARIATION_PASSWORD)
            suffixField = input("固定代理域名后缀", "yuceyang.cn68.ugdocker.link")
            addView(aliasField, matchWidth())
            addView(username, matchWidth())
            addView(password, matchWidth())
            addView(suffixField, matchWidth())
            addView(hint("别名就是 ug.link 后面的名字。远程地址会随 NAS 重新注册而变化（cn68 → cn11），" +
                "别名不用改；固定后缀决定你访问时用的主机名，填一次即可长期不变。"), matchWidth())
            loginStateView = TextView(this@MainActivity).apply {
                textSize = 13f
                setPadding(0, 0, 0, dp(8))
            }
            addView(loginStateView, matchWidth())
            loginButton = primaryButton("保存并测试登录") { testLogin() }
            addView(loginButton, matchWidth())
        })

        page.addView(card("代理路由", "填应用端口即可，主机名按「端口 + 固定后缀」自动生成。") {
            routePort = input("应用端口", "5006", InputType.TYPE_CLASS_NUMBER)
            routeHost = input("主机名（高级，留空自动生成）", "app-5006-****.ugdocker.link")
            routeSystem = android.widget.CheckBox(this@MainActivity).apply {
                text = "NAS 系统服务（如 9443 后台；经中继访问，不走向端口映射）"
                textSize = 13f
                setTextColor(COLOR_TEXT)
                setPadding(0, dp(4), 0, dp(8))
            }
            addView(routePort, matchWidth())
            addView(routeHost, matchWidth())
            addView(routeSystem, matchWidth())
            addView(primaryButton("添加路由") { saveRoute() }, matchWidth())
            routeList = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, dp(6), 0, 0)
            }
            addView(routeList, matchWidth())
        })

        page.addView(card("HTTPS 根证书", "只有「浏览器类」应用需要。思源等 Go 应用请用上面的 HTTP 入口，无需证书。") {
            caState = TextView(this@MainActivity).apply {
                textSize = 13f
                setTextColor(COLOR_MUTED)
                setPadding(0, 0, 0, dp(8))
            }
            addView(caState, matchWidth())
            addView(primaryButton("一键安装根证书") { installLocalCa() }, matchWidth())
            addView(secondaryButton("导出证书文件到 Download") { exportCa() }, matchWidth())
        })

        page.addView(card("VPN", "开启后系统 DNS 才会把已添加的域名交给 GatePass 处理。") {
            vpnState = TextView(this@MainActivity).apply {
                textSize = 13f
                setTextColor(COLOR_MUTED)
                setPadding(0, 0, 0, dp(8))
            }
            addView(vpnState, matchWidth())
            startVpnButton = primaryButton("启动 GatePass VPN") { requestVpn() }
            stopVpnButton = secondaryButton("停止 VPN") {
                startService(Intent(this@MainActivity, GatePassVpnService::class.java).setAction(GatePassVpnService.ACTION_STOP))
                DiagLog.log("已请求停止 VPN")
                showStatus("已请求停止 VPN")
                vpnState.postDelayed({ refreshVpnState() }, 1200)
            }
            addView(startVpnButton, matchWidth())
            addView(stopVpnButton, matchWidth())
            status = TextView(this@MainActivity).apply {
                text = "就绪"
                textSize = 13f
                setTextColor(COLOR_MUTED)
                setPadding(0, dp(6), 0, 0)
            }
            addView(status, matchWidth())
        })

        page.addView(card("运行日志", "排查问题时看这里；也可用 adb logcat -s GatePass。") {
            logView = TextView(this@MainActivity).apply {
                text = "（暂无日志）"
                textSize = 11f
                typeface = Typeface.MONOSPACE
                setTextIsSelectable(true)
                setPadding(dp(10), dp(10), dp(10), dp(10))
                background = rounded(COLOR_LOG_BG, dp(8))
                maxLines = 18
            }
            addView(logView, matchWidth())
            addView(secondaryButton("清空日志") { DiagLog.clear() }, matchWidth())
        })

        page.addView(card("多终端配置", "导出的 JSON 与 PC 端 GatePass 通用，可在多台设备间同步账号与路由。") {
            addView(primaryButton("导出配置（含密码）") { exportPortable(includePassword = true) }, matchWidth())
            addView(secondaryButton("导出配置（不含密码）") { exportPortable(includePassword = false) }, matchWidth())
            addView(secondaryButton("导入配置…") { importPortable() }, matchWidth())
        })

        page.addView(card("安全", "账号、会话、网关令牌与证书私钥均以 Android Keystore 加密保存。") {
            addView(dangerButton("清除本机保存的账号与会话") {
                store.clearSecrets()
                password.setText("")
                refreshCaState()
                showStatus("已清除保存的密码、会话和证书")
            }, matchWidth())
        })

        setContentView(ScrollView(this).apply {
            setBackgroundColor(COLOR_BG)
            addView(page)
        })
    }

    private fun buildHeader() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, dp(8), 0, dp(12))
        addView(TextView(this@MainActivity).apply {
            text = "GatePass"
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(COLOR_PRIMARY_DARK)
        })
        addView(TextView(this@MainActivity).apply {
            text = "NAS 应用免登录代理 · 独立 Android 客户端"
            textSize = 13f
            setTextColor(COLOR_MUTED)
            setPadding(0, dp(4), 0, 0)
        })
    }

    /** A titled card with rounded background and a thin accent bar. */
    private fun card(title: String, subtitle: String, content: LinearLayout.() -> Unit): View {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
            background = rounded(Color.WHITE, dp(14))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { bottomMargin = dp(12) }
        }
        box.addView(TextView(this).apply {
            text = title
            textSize = 17f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(COLOR_PRIMARY_DARK)
        })
        box.addView(TextView(this).apply {
            text = subtitle
            textSize = 12f
            setTextColor(COLOR_MUTED)
            setPadding(0, dp(2), 0, dp(10))
        })
        box.content()
        return box
    }

    // ---------------------------------------------------------------- routes

    /**
     * Reflects the stored NAS session in the login card: text describes the state, and the button
     * changes colour so "am I logged in?" is answerable at a glance.
     */
    private fun refreshLoginState() {
        if (!::loginStateView.isInitialized || !::loginButton.isInitialized) return
        val state = store.sessionState()
        val age = store.sessionAgeMs()
        val ttlHours = SecureSettingsStore.SESSION_TTL_MS / 3_600_000L

        when (state) {
            SecureSettingsStore.SessionState.Valid -> {
                val left = ttlHours - (age ?: 0L) / 3_600_000L
                loginStateView.text = "● 已登录 NAS · 约 ${left.coerceAtLeast(0)} 小时后到期"
                loginStateView.setTextColor(COLOR_PRIMARY_DARK)
                stylePrimary(loginButton, "已登录 · 重新登录")
            }
            SecureSettingsStore.SessionState.Expiring -> {
                val left = ttlHours - (age ?: 0L) / 3_600_000L
                loginStateView.text = "● 已登录，但约 ${left.coerceAtLeast(0)} 小时后到期，建议重新登录"
                loginStateView.setTextColor(COLOR_WARN)
                styleWarn(loginButton, "即将过期 · 点此重新登录")
            }
            SecureSettingsStore.SessionState.Expired -> {
                loginStateView.text = "● 会话已过期（超过 ${ttlHours} 小时），请重新登录"
                loginStateView.setTextColor(COLOR_DANGER)
                styleDanger(loginButton, "会话已过期 · 重新登录")
            }
            SecureSettingsStore.SessionState.Missing -> {
                loginStateView.text = "○ 尚未登录 NAS"
                loginStateView.setTextColor(COLOR_MUTED)
                stylePrimary(loginButton, "保存并测试登录")
            }
            SecureSettingsStore.SessionState.Unknown -> {
                loginStateView.text = "○ 有会话凭据，但无法判断是否过期"
                loginStateView.setTextColor(COLOR_MUTED)
                stylePrimary(loginButton, "重新登录以刷新有效期")
            }
        }
    }

    private fun stylePrimary(button: Button, label: String) {
        button.text = label
        button.setTextColor(android.graphics.Color.WHITE)
        button.background = rounded(COLOR_PRIMARY, dp(10))
    }

    private fun styleWarn(button: Button, label: String) {
        button.text = label
        button.setTextColor(android.graphics.Color.WHITE)
        button.background = rounded(COLOR_WARN, dp(10))
    }

    private fun styleDanger(button: Button, label: String) {
        button.text = label
        button.setTextColor(android.graphics.Color.WHITE)
        button.background = rounded(COLOR_DANGER, dp(10))
    }

    private fun refreshRoutes() {
        val routes = store.loadRoutes().sorted()
        routeList.removeAllViews()
        if (routes.isEmpty()) {
            routeList.addView(TextView(this).apply {
                text = "还没有添加路由。添加后每个域名都会出现「开启 / 关闭 HTTP 入口」和「复制地址」。"
                textSize = 12f
                setTextColor(COLOR_MUTED)
                setPadding(0, dp(6), 0, dp(2))
            })
            return
        }
        routes.forEach { routeList.addView(buildRouteRow(it), matchWidth()) }
    }

    private fun buildRouteRow(host: String): View {
        val enabled = store.isHttpIngressEnabled(host)
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = rounded(if (enabled) COLOR_ENABLED_BG else COLOR_LOG_BG, dp(10))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { bottomMargin = dp(8) }
        }
        row.addView(TextView(this).apply {
            text = if (store.routeKind(host) == ProxyRoute.KIND_SYSTEM) "$host  · NAS 系统服务" else host
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(COLOR_TEXT)
        })
        val url = store.httpIngressUrl(host)
        row.addView(TextView(this).apply {
            text = if (enabled) url else "HTTP 入口已关闭"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(if (enabled) COLOR_PRIMARY_DARK else COLOR_MUTED)
            setPadding(0, dp(3), 0, dp(8))
        })
        // Two rows of actions: a single row of four buttons became too narrow on small screens
        // and collapsed "删除" into a vertical stack of single characters.
        val primaryActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.START
            isBaselineAligned = false
        }
        primaryActions.addView(smallButton(if (enabled) "关闭入口" else "开启入口") {
            store.setHttpIngressEnabled(host, !enabled)
            DiagLog.log("${if (enabled) "关闭" else "开启"} HTTP 入口: $host")
            refreshRoutes()
            showStatus(if (enabled) "已关闭 $host 的 HTTP 入口" else "已开启 $host 的 HTTP 入口")
        })
        if (enabled) {
            primaryActions.addView(smallButton("复制地址") {
                copyToClipboard(url)
                showStatus("已复制 $host 的入口地址")
            })
        }
        val secondaryActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.START
            isBaselineAligned = false
            setPadding(0, dp(6), 0, 0)
        }
        if (enabled) secondaryActions.addView(smallButton("测试连通") { testRoute(host) })
        secondaryActions.addView(smallButton("删除", danger = true) {
            store.removeRoute(host)
            refreshRoutes()
            showStatus("已删除路由 $host")
        })
        row.addView(primaryActions)
        row.addView(secondaryActions)
        return row
    }

    /**
     * Probes the HTTP ingress for one host so users can confirm a route works before pointing an
     * app at it. Runs off the UI thread; the result lands in the status line and the log.
     */
    private fun testRoute(host: String) {
        showStatus("正在测试 $host …")
        Thread({
            val url = store.httpIngressUrl(host)
            val result = runCatching {
                val connection = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                connection.connectTimeout = 8000
                connection.readTimeout = 15000
                connection.requestMethod = "GET"
                try {
                    connection.responseCode to (connection.headerFields["Server"]?.firstOrNull() ?: "")
                } finally {
                    connection.disconnect()
                }
            }
            runOnUiThread {
                result.onSuccess { (code, server) ->
                    val ok = code in 200..499
                    DiagLog.log("路由测试 $host → HTTP $code${if (server.isNotBlank()) " ($server)" else ""}")
                    showStatus(
                        when {
                            code == 403 -> "入口已关闭，请先点「开启入口」"
                            code == 421 -> "未配置该域名路由"
                            code == 401 -> "NAS 未登录，请先完成登录"
                            ok -> "连接正常（HTTP $code）"
                            else -> "响应异常（HTTP $code）"
                        },
                    )
                }.onFailure { error ->
                    DiagLog.error("路由测试失败 $host", error)
                    showStatus("测试失败：${error.message ?: "无法连接"}")
                }
            }
        }, "gatepass-route-test").start()
    }

    private fun saveRoute() {
        val suffix = suffixField.text.toString().trim().removePrefix(".")
        val port = routePort.text.toString().trim().removePrefix("app-").removePrefix("-")
        val system = routeSystem.isChecked
        val typed = routeHost.text.toString().trim()
        // A blank hostname means "generate it from the port and the fixed suffix".
        val host = typed.ifBlank {
            if (port.isBlank()) {
                showStatus("请填写应用端口")
                return
            }
            if (suffix.isBlank()) {
                showStatus("请先填写固定代理域名后缀")
                return
            }
            "app-${port}-$suffix"
        }
        val route = ProxyRoute.parse(host, if (system) ProxyRoute.KIND_SYSTEM else ProxyRoute.KIND_APP)
        if (route == null) {
            showStatus("域名格式不正确")
            return
        }
        store.addRoute(route.host)
        store.setRouteKind(route.host, route.kind)
        store.setHttpIngressEnabled(route.host, true)
        routePort.setText("")
        routeHost.setText("")
        routeSystem.isChecked = false
        refreshRoutes()
        showStatus("已添加路由 ${route.host}，HTTP 入口默认开启")
    }

    // ---------------------------------------------------------------- actions

    private fun testLogin() {
        val alias = aliasField.text.toString().trim()
        val suffix = suffixField.text.toString().trim().removePrefix(".")
        val user = username.text.toString().trim()
        // An imported config restores the password into storage but leaves the field empty (it is
        // a password field). Fall back to the stored one instead of refusing to log in.
        val stored = store.loadNas().password
        val pass = password.text.toString().ifBlank { stored }
        if (alias.isBlank() || user.isBlank() || pass.isBlank()) {
            showStatus("请填写 UGREENlink 别名、用户名和密码")
            return
        }
        store.saveAlias(alias)
        if (suffix.isNotBlank()) store.saveFixedSuffix(suffix)
        showStatus("正在连接 NAS…")
        Thread({
            val result = runCatching {
                val client = UgosAuthClient(log = DiagLog::log)
                // Resolve the live host first: the manual address may point at a suffix the NAS
                // has since abandoned. Fall back to the stored address if the lookup fails.
                val manual = store.loadNas().baseUrl
                val base = runCatching { client.resolveBase(alias, manual, user) }
                    .getOrElse { manual.trim().trimEnd('/') }
                if (base.isBlank()) throw IllegalStateException("无法解析 $alias 的访问地址，请检查别名或网络")
                // Persist the address actually used, so later gateway-token calls hit the same host.
                store.saveNas(base, user, pass)
                val session = client.loginAt(base, user, pass)
                // Remember which suffix/relay the NAS reports right now — the proxy dials these.
                var repairedSuffix: String? = null
                client.lookupByAlias(alias)?.let { node ->
                    store.saveDiscovered(node.domainSuffix, node.relayHost)
                    // Repair only a *truncated* suffix, never replace the one the user chose: the
                    // whole point of the fixed suffix is that it survives the NAS re-registering
                    // (cn68 → cn11). An upgrade from 0.2.x left `cn68.ugdocker.link` with the
                    // account label dropped, which would generate `app-5006-cn68.ugdocker.link`.
                    val fixed = store.fixedSuffix()
                    val repaired = when {
                        fixed.isBlank() -> node.domainSuffix
                        // Same domain family but missing the leading label(s).
                        node.domainSuffix.isNotBlank() &&
                            node.domainSuffix.endsWith(fixed, ignoreCase = true) &&
                            node.domainSuffix.length > fixed.length -> node.domainSuffix
                        else -> ""
                    }
                    if (repaired.isNotBlank()) {
                        store.saveFixedSuffix(repaired)
                        repairedSuffix = repaired
                    }
                }
                Triple(base, session, repairedSuffix)
            }
            runOnUiThread {
                result.onSuccess { (base, session, repaired) ->
                    store.saveSession(session.sessionToken, session.cookieHeader)
                    password.setText("")
                    password.clearFocus()
                    if (repaired != null) suffixField.setText(repaired)
                    refreshLoginState()
                    refreshRoutes()
                    showStatus(
                        if (repaired != null) "登录成功，已补全固定后缀为 $repaired"
                        else "NAS 登录成功（$base）",
                    )
                }.onFailure { error ->
                    DiagLog.error("NAS 登录失败", error)
                    showStatus(error.message ?: "NAS 登录失败")
                }
            }
        }, "gatepass-login-test").start()
    }

    /**
     * One tap, then two taps in Android's own UI. The platform forbids an app from installing a
     * CA into the user trust store silently — the user must confirm in Settings — so this
     * generates the certificate, writes it to Download, and opens the exact settings page.
     */
    private fun installLocalCa() {
        runCatching {
            val written = writeCaToDownloads()
            DiagLog.log("已生成 CA 文件: $written")
            resumeVpnAfterSettings = GatePassVpnService.isRunning
            openCaInstallSettings()
            showStatus("请在「从存储设备安装证书」中选择 Download/gatepass-ca.crt")
        }.onFailure { error ->
            DiagLog.error("准备证书安装失败", error)
            showStatus(error.message ?: "无法准备证书安装")
        }
    }

    /**
     * Writes the PEM into the public Downloads folder via MediaStore.
     *
     * A plain File write to Environment.getExternalStoragePublicDirectory silently does nothing
     * on Android 10+ without legacy storage, which made the "export" button appear to work while
     * leaving a stale certificate behind.
     */
    private fun writeCaToDownloads(): String {
        val der = CertificateAuthority(this).rootCertificateDer()
        val body = android.util.Base64.encodeToString(der, android.util.Base64.NO_WRAP).chunked(64).joinToString(NEWLINE)
        val pem = "-----BEGIN CERTIFICATE-----$NEWLINE" + body + "${NEWLINE}-----END CERTIFICATE-----$NEWLINE"
        val bytes = pem.toByteArray(Charsets.US_ASCII)

        val resolver = contentResolver
        // Replace any previous export first: MediaStore would otherwise create
        // "gatepass-ca (1).crt" next to the stale file, and the user would install the old CA.
        runCatching {
            resolver.delete(
                android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                "${android.provider.MediaStore.MediaColumns.DISPLAY_NAME} LIKE ?",
                arrayOf("gatepass-ca%"),
            )
        }

        val collection = android.content.ContentValues().apply {
            put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, CA_FILE_NAME)
            put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "application/x-x509-ca-cert")
            put(
                android.provider.MediaStore.MediaColumns.RELATIVE_PATH,
                android.os.Environment.DIRECTORY_DOWNLOADS,
            )
            put(android.provider.MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val uri = resolver.insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, collection)
            ?: throw IllegalStateException("无法在 Download 目录创建文件")

        resolver.openOutputStream(uri)?.use { it.write(bytes) }
            ?: throw IllegalStateException("无法写入证书文件")

        resolver.update(
            uri,
            android.content.ContentValues().apply {
                put(android.provider.MediaStore.MediaColumns.IS_PENDING, 0)
            },
            null,
            null,
        )
        DiagLog.log("CA 已写入 Download/$CA_FILE_NAME（${bytes.size} 字节）")
        return "Download/$CA_FILE_NAME"
    }

    /**
     * Opens Settings → Security → Credential storage. OEM skins differ, so fall back through the
     * documented intents until one resolves; the user then taps "Install from storage".
     */
    private fun openCaInstallSettings() {
        val candidates = listOf(
            Intent("com.android.settings.SECURITY_SETTINGS"),
            Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS),
            Intent(android.provider.Settings.ACTION_SETTINGS),
        )
        for (intent in candidates) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (runCatching { startActivity(intent) }.isSuccess) return
        }
        throw IllegalStateException("无法打开系统设置，请手动前往 设置 → 安全 → 凭据存储")
    }

    private fun exportCa() {
        runCatching {
            val path = writeCaToDownloads()
            DiagLog.log("已导出 CA: $path")
            showStatus("已导出到 $path")
        }.onFailure { error ->
            DiagLog.error("导出 CA 失败", error)
            showStatus(error.message ?: "导出 CA 失败")
        }
    }

    private fun requestVpn() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnLauncher.launch(prepare) else startVpnService()
    }

    private fun startVpnService() {
        val intent = Intent(this, GatePassVpnService::class.java).setAction(GatePassVpnService.ACTION_START)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent) else startService(intent)
        DiagLog.log("已请求启动 VPN 服务")
        showStatus("VPN 正在启动")
        vpnState.postDelayed({ refreshVpnState() }, 2500)
    }

    private fun refreshVpnState() {
        if (!::vpnState.isInitialized) return
        val active = GatePassVpnService.isRunning
        vpnState.text = if (active) {
            "● 已连接 · 入口端口 ${LocalHttpIngress.DEFAULT_PORT}"
        } else {
            "○ 未连接"
        }
        vpnState.setTextColor(if (active) COLOR_PRIMARY_DARK else COLOR_MUTED)
        // While the tunnel is up, "Start" is meaningless and "Stop" is the only sensible action —
        // so dim the former and promote the latter.
        if (::startVpnButton.isInitialized && ::stopVpnButton.isInitialized) {
            startVpnButton.isEnabled = !active
            startVpnButton.alpha = if (active) 0.45f else 1f
            stopVpnButton.isEnabled = active
            stopVpnButton.alpha = if (active) 1f else 0.45f
            if (active) {
                stopVpnButton.setTextColor(android.graphics.Color.WHITE)
                stopVpnButton.background = rounded(COLOR_PRIMARY, dp(10))
            } else {
                stopVpnButton.setTextColor(COLOR_PRIMARY_DARK)
                stopVpnButton.background = rounded(COLOR_LOG_BG, dp(10))
            }
        }
    }

    private fun refreshCaState() {
        if (!::caState.isInitialized) return
        caState.text = "证书由本应用自动生成，无需你填写或上传。" +
            "点「一键安装」后，在系统弹窗确认即可；该证书只用于本机，删除应用即失效。"
    }

    private fun restoreFields() {
        val saved = store.loadNas()
        aliasField.setText(saved.alias)
        suffixField.setText(store.fixedSuffix())
        username.setText(saved.username)
        refreshRoutes()
    }

    private fun copyToClipboard(text: String) {
        getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText("GatePass", text))
    }

    // ---------------------------------------------------------------- portable config

    /** Opens the system "save as" picker; the actual write happens in onActivityResult. */
    private fun exportPortable(includePassword: Boolean) {
        pendingExportIncludePassword = includePassword
        val name = "gatepass-config${if (includePassword) "" else "-nopass"}.json"
        runCatching { exportLauncher.launch(name) }
            .onFailure { showStatus("无法打开文件选择器: ${it.message}") }
    }

    private fun writePortable(uri: android.net.Uri, includePassword: Boolean) {
        runCatching {
            val data = store.toPortable(includePassword)
            val text = PortableConfig.encode(data, includePassword)
            contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray(Charsets.UTF_8)) }
                ?: throw IllegalStateException("无法写入所选文件")
            DiagLog.log("已导出配置: ${data.routes.size} 条路由，含密码=$includePassword")
            showStatus(
                if (includePassword) "已导出（含密码，请妥善保管）" else "已导出（不含密码）",
            )
        }.onFailure {
            DiagLog.error("导出配置失败", it)
            showStatus(it.message ?: "导出失败")
        }
    }

    /** Opens the system file picker; parsing happens in onActivityResult. */
    private fun importPortable() {
        runCatching {
            importLauncher.launch(arrayOf("application/json", "text/plain", "application/octet-stream"))
        }.onFailure { showStatus("无法打开文件选择器: ${it.message}") }
    }

    private fun readPortable(uri: android.net.Uri) {
        runCatching {
            val text = contentResolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) }
                ?: throw IllegalStateException("无法读取所选文件")
            val data = PortableConfig.decode(text)
            val count = store.applyPortable(data)
            DiagLog.log("已导入配置: ${data.username} @ ${data.alias.ifBlank { data.authBase }}，${count} 条路由")
            aliasField.setText(data.alias)
            suffixField.setText(data.domainSuffix)
            username.setText(data.username)
            if (data.password.isNotBlank()) password.setText(data.password)
            refreshRoutes()
            showStatus("已导入 $count 条路由；如 VPN 正在运行请重启")
        }.onFailure {
            DiagLog.error("导入配置失败", it)
            showStatus(it.message ?: "导入失败")
        }
    }

    // ---------------------------------------------------------------- widgets

    private fun input(hintText: String, placeholder: String, variation: Int = 0) = EditText(this).apply {
        hint = placeholder
        textSize = 15f
        inputType = InputType.TYPE_CLASS_TEXT or variation
        setSingleLine(true)
        setPadding(dp(12), dp(10), dp(12), dp(10))
        background = rounded(COLOR_LOG_BG, dp(8))
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(8) }
    }

    /** Small muted paragraph used for explanatory copy inside a card. */
    private fun hint(value: String) = TextView(this).apply {
        text = value
        textSize = 12f
        setTextColor(COLOR_MUTED)
        setPadding(0, 0, 0, dp(8))
    }

    private fun primaryButton(value: String, action: () -> Unit) = Button(this).apply {
        text = value
        textSize = 15f
        isAllCaps = false
        setTextColor(Color.WHITE)
        background = rounded(COLOR_PRIMARY, dp(10))
        setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(8) }
    }

    private fun secondaryButton(value: String, action: () -> Unit) = Button(this).apply {
        text = value
        textSize = 14f
        isAllCaps = false
        setTextColor(COLOR_PRIMARY_DARK)
        background = rounded(COLOR_LOG_BG, dp(10))
        setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(8) }
    }

    private fun dangerButton(value: String, action: () -> Unit) = Button(this).apply {
        text = value
        textSize = 14f
        isAllCaps = false
        setTextColor(COLOR_DANGER)
        background = rounded(COLOR_DANGER_BG, dp(10))
        setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        )
    }

    private fun smallButton(value: String, danger: Boolean = false, action: () -> Unit) = Button(this).apply {
        text = value
        textSize = 12f
        isAllCaps = false
        minHeight = 0
        minimumHeight = 0
        setPadding(dp(12), dp(4), dp(12), dp(4))
        setTextColor(if (danger) COLOR_DANGER else COLOR_PRIMARY_DARK)
        background = rounded(if (danger) COLOR_DANGER_BG else Color.WHITE, dp(8))
        setOnClickListener { action() }
        isSingleLine = true
        // Stop the row from squeezing the label into a vertical stack when space is tight.
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { marginEnd = dp(8) }
    }

    private fun rounded(color: Int, radius: Int) = GradientDrawable().apply {
        setColor(color)
        cornerRadius = radius.toFloat()
    }

    private fun showStatus(message: String) {
        status.text = message
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun matchWidth() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    )

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val REQUEST_VPN = 501
        private const val REQUEST_NOTIFICATIONS = 502
        private const val REQUEST_EXPORT = 503
        private const val REQUEST_IMPORT = 504
        private const val CA_FILE_NAME = "gatepass-ca.crt"
        private const val NEWLINE = "\n"

        private val COLOR_BG = Color.parseColor("#F5F7F6")
        private val COLOR_PRIMARY = Color.parseColor("#166534")
        private val COLOR_PRIMARY_DARK = Color.parseColor("#14532D")
        private val COLOR_TEXT = Color.parseColor("#1F2937")
        private val COLOR_MUTED = Color.parseColor("#6B7280")
        private val COLOR_WARN = Color.parseColor("#C2410C")
        private val COLOR_LOG_BG = Color.parseColor("#F1F5F9")
        private val COLOR_ENABLED_BG = Color.parseColor("#ECFDF5")
        private val COLOR_DANGER = Color.parseColor("#B91C1C")
        private val COLOR_DANGER_BG = Color.parseColor("#FEF2F2")
    }
}
