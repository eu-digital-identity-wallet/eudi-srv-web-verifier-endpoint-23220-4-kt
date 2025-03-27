package eu.europa.ec.eudi.verifier.endpoint.adapter.out.lotl

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.URI
import java.security.KeyStore

class FetchLOTLCertificatesDSSTest {

    @Test
    fun `get certs`() = runTest  {

        val fetchLOTLCertificatesDSS = FetchLOTLCertificatesDSS()

        val result = fetchLOTLCertificatesDSS(
            URI("https://ec.europa.eu/tools/lotl/eu-lotl.xml").toURL()
        )

        assertTrue(result.isSuccess)
        assertTrue(result.getOrNull()?.isNotEmpty() == true)

        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(null, null)

        val certs = result.getOrNull()
        certs?.forEachIndexed { index, cert ->
            keyStore.setCertificateEntry("cert_$index", cert)
        }

        assertEquals(certs?.size, keyStore.aliases().toList().size)
    }
}