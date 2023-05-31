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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.JwtSecuredAuthorizationRequestTO
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import org.junit.jupiter.api.Assertions
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import java.io.ByteArrayInputStream

object VerifierApiClient {

    fun loadInitTransactionTO(testResource: String): InitTransactionTO =
        Json.decodeFromString(TestUtils.loadResource(testResource))

    @OptIn(ExperimentalSerializationApi::class)
    fun initTransaction(client: WebTestClient, initTransactionTO: InitTransactionTO): JwtSecuredAuthorizationRequestTO {
        return client.post().uri(VerifierApi.initTransactionPath)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .bodyValue(initTransactionTO)
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult().responseBodyContent!!.let { byteArray ->
            ByteArrayInputStream(byteArray).use { Json.decodeFromStream(it) }
        }
    }

    /**
     * Verifier application to Verifier Backend, get authorisation response
     *
     * As per OpenId4VP draft 18, section 10.5, Figure 3:
     * - (request) Verifier to Verifier Response endpoint, flow "(8) fetch response data (transaction-id, response_code)"
     * - (response) Verifier ResponseEndpoint to Verifier, flow "(9) response data (VP Token, Presentation Submission)"
     *
     * As per ISO 23220-4, Appendix B:
     * - (request) mdocVerification application Internet frontend to Internet Web Service, flow "18 HTTPs POST to response_uri [section B.3.2.2]
     * - (response) Internet Web Service to mdocVerification application Internet frontend, flow "20 return status and conditionally return data"
     */
    fun getWalletResponse(client: WebTestClient, presentationId: PresentationId, nonce: Nonce): String {
        val walletResponseUri =
            VerifierApi.walletResponsePath.replace("{presentationId}", presentationId.value) + "?nonce=${nonce.value}"

        // when
        val responseSpec = client.get().uri(walletResponseUri)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
        val returnResult = responseSpec.expectBody().returnResult()
        returnResult.status.also { println("response status: $it") }
        returnResult.responseHeaders.also { println("response headers: $it") }
        returnResult.responseBodyContent?.let {
            println("response body content:\n${TestUtils.prettyPrintJson(String(it))}")
        }

        // then
        Assertions.assertEquals(HttpStatus.OK, returnResult.status)

        return returnResult.responseBodyContent?.let { String(it) }!!
    }
}
