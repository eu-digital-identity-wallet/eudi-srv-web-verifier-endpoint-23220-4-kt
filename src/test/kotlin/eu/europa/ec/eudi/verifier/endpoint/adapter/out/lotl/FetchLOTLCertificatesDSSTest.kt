/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.lotl

import arrow.core.raise.result
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustedListConfig
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import java.net.URI
import java.security.KeyStore

class FetchLOTLCertificatesDSSTest {

//    @Test
    fun `get certs`() = runTest {
        val fetchLOTLCertificatesDSS = FetchLOTLCertificatesDSS()

        val result = fetchLOTLCertificatesDSS(
            TrustedListConfig(
                URI("https://ec.europa.eu/tools/lotl/eu-lotl.xml").toURL(),
                null,
                "0 *",
                keystoreConfig = null,
            ),
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
