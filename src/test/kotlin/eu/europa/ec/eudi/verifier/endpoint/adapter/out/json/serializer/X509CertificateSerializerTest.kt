package eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.serializer

import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import org.springframework.core.io.ClassPathResource
import java.security.KeyStore
import java.security.cert.X509Certificate

@VerifierApplicationTest(classes = [InstantSerializer::class])
class X509CertificateSerializerTest {
    private val serializer = Json {
        serializersModule = SerializersModule {
            contextual(X509Certificate::class, X509CertificateSerializer)
        }
    }

    private val keystore = ClassPathResource("test-cert.jks").inputStream.use {
        KeyStore.getInstance("JKS").apply {
            load(it, "".toCharArray())
        }
    }

    @Test
    fun `serialize and deserialize X509Certificate`() {
        val certificate = keystore.getCertificate("client-id") ?: fail("Certificate with alias 'client-id' not found")

        val encoded = serializer.encodeToString(X509CertificateSerializer, certificate as X509Certificate)
        assertNotNull(encoded)

        val decoded = serializer.decodeFromString<X509Certificate>(encoded)

        assertEquals(certificate.type, decoded.type)
        assertEquals(certificate.serialNumber, decoded.serialNumber)
        assertEquals(certificate.sigAlgName, decoded.sigAlgName)
        assertEquals(certificate.subjectX500Principal.name, certificate.subjectX500Principal.name)
        assertArrayEquals(certificate.signature, certificate.signature)
    }
}
