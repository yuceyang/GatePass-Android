package com.yuceyang.gatepassandroid.proxy

import android.content.Context
import com.yuceyang.gatepassandroid.data.SecureSettingsStore
import com.yuceyang.gatepassandroid.diag.DiagLog
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/** Creates a private local CA and short-lived host certificates for explicit TLS interception. */
class CertificateAuthority(context: Context) {
    private val store = SecureSettingsStore(context)
    private val leafContexts = ConcurrentHashMap<String, SSLContext>()
    private val caMaterial: SecureSettingsStore.CaMaterial by lazy { loadOrCreateCa() }

    fun rootCertificateDer(): ByteArray = caMaterial.certificateDer.copyOf()

    fun serverContext(host: String): SSLContext {
        val normalizedHost = host.trim().lowercase()
        require(normalizedHost.isNotBlank() && normalizedHost.length <= 253) { "Invalid certificate host" }
        leafContexts[normalizedHost]?.let { return it }
        return createLeafContext(normalizedHost).also { leafContexts[normalizedHost] = it }
    }

    private fun loadOrCreateCa(): SecureSettingsStore.CaMaterial {
        store.loadCaMaterial()?.let { return it }
        ensureProvider()
        val keyPair = generateKeyPair()
        val now = System.currentTimeMillis()
        val subject = X500Name(CA_SUBJECT)
        val builder = JcaX509v3CertificateBuilder(
            subject,
            randomSerial(),
            Date(now - DAY_MS),
            Date(now + ROOT_VALIDITY_MS),
            subject,
            keyPair.public,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        val certificate = sign(builder, keyPair.private)
        val material = SecureSettingsStore.CaMaterial(keyPair.private.encoded, certificate.encoded)
        store.saveCaMaterial(material.privateKeyPkcs8, material.certificateDer)
        return material
    }

    private fun createLeafContext(host: String): SSLContext {
        ensureProvider()
        val caPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(caMaterial.privateKeyPkcs8))
        val caCertificate = parseCertificate(caMaterial.certificateDer)

        // Reuse a still-valid leaf from disk: regenerating it on every restart forced clients to
        // re-trust a new certificate and wasted a 2048-bit keygen per host.
        val cached = store.loadLeaf(host)
        val leafPrivateKey: PrivateKey
        val leafCertificate: X509Certificate
        if (cached != null) {
            leafPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(cached.privateKeyPkcs8))
            leafCertificate = parseCertificate(cached.certificateDer)
            DiagLog.log("复用已缓存证书 $host")
        } else {
            val leafPair = generateKeyPair()
            val now = System.currentTimeMillis()
            // Issuer MUST match the CA subject, otherwise the chain does not verify.
            val builder = JcaX509v3CertificateBuilder(
                X500Name(CA_SUBJECT),
                randomSerial(),
                Date(now - 5 * 60 * 1000),
                Date(now + LEAF_VALIDITY_MS),
                X500Name("CN=$host"),
                leafPair.public,
            )
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment))
            builder.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
            builder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, host)))
            leafCertificate = sign(builder, caPrivateKey)
            leafPrivateKey = leafPair.private
            store.saveLeaf(host, leafPrivateKey.encoded, leafCertificate.encoded, now + LEAF_VALIDITY_MS)
            DiagLog.log("已生成并缓存证书 $host")
        }

        val password = ByteArray(24).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }.toCharArray()
        val keyStore = java.security.KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("gatepass-leaf", leafPrivateKey, password, arrayOf(leafCertificate, caCertificate))
        }
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(keyStore, password)
        }.keyManagers
        return SSLContext.getInstance("TLS").apply { init(keyManagers, null, SecureRandom()) }
    }

    private fun sign(builder: JcaX509v3CertificateBuilder, key: PrivateKey): X509Certificate {
        // Sign with the platform JCA provider: Android ships a stripped-down "BC" that does not
        // register SHA256withRSA, so pointing the signer at BouncyCastle fails at runtime.
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(key)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun parseCertificate(encoded: ByteArray): X509Certificate =
        java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(encoded.inputStream()) as X509Certificate

    private fun generateKeyPair(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun randomSerial(): BigInteger = BigInteger(159, SecureRandom()).abs().coerceAtLeast(BigInteger.ONE)

    private fun ensureProvider() {
        // Do not add the full BouncyCastle provider: on Android it collides with the platform's
        // stripped "BC" provider and breaks signing. Only the cert-builder classes are used.
    }

    companion object {
        private const val CA_SUBJECT = "CN=GatePass Android Local Root CA"
        private const val DAY_MS = 24L * 60 * 60 * 1000
        private const val ROOT_VALIDITY_MS = 3650L * DAY_MS
        private const val LEAF_VALIDITY_MS = 2L * DAY_MS
    }
}
