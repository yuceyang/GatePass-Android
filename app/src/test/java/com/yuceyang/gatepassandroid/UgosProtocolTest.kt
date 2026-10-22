package com.yuceyang.gatepassandroid

import com.yuceyang.gatepassandroid.auth.UgosAuthClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class UgosProtocolTest {
    @Test
    fun decodesBase64PemFromRsaTokenHeader() {
        val pem = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"
        val header = Base64.getEncoder().encodeToString(pem.toByteArray())
        assertEquals(pem, UgosAuthClient.decodePublicKeyPem(header))
    }

    @Test
    fun extractsApplicationPortFromHost() {
        assertEquals("5006", UgosAuthClient.extractPortFromHost("app-5006-example.ugdocker.link"))
        assertEquals("16601", UgosAuthClient.extractPortFromHost("app16601-example.ugdocker.link"))
        assertEquals("", UgosAuthClient.extractPortFromHost("service.example.com"))
    }

    @Test
    fun rejectsNonPemTokenHeader() {
        val header = Base64.getEncoder().encodeToString("not-a-key".toByteArray())
        val failure = runCatching { UgosAuthClient.decodePublicKeyPem(header) }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
    }
}
