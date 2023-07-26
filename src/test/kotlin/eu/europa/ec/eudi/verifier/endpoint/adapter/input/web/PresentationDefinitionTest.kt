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

import eu.europa.ec.eudi.prex.PresentationExchange
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
internal class PresentationDefinitionTest {

    private val log: Logger = LoggerFactory.getLogger(PresentationDefinitionTest::class.java)

    @Autowired
    private lateinit var client: WebTestClient

    @Test
    fun `post presentation definition returns 200`() {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("00-presentationDefinition.json")
        log.info("initTransaction: $initTransaction")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        log.info("transactionInitialized: $transactionInitialized")
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        log.info("requestId: ${requestId.value}")
    }

    @Test
    fun `get presentation definition returns 200`() {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("00-presentationDefinition.json")
        log.info("initTransaction: $initTransaction")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        log.info("transactionInitialized: $transactionInitialized")
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        log.info("requestId: ${requestId.value}")

        val relativeRequestUri =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0")!!)
        log.info("relativeRequestUri: $relativeRequestUri")

        // then
        val getResponse = client.get().uri(relativeRequestUri.value)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult()
        val getResponseString = String(getResponse.responseBodyContent!!)
        log.info("response: $getResponseString")

        val (_, payload) = TestUtils.parseJWTIntoClaims(getResponseString)

        val responsePresentationDefinition = payload["presentation_definition"]?.let {
            PresentationExchange.jsonParser.decodePresentationDefinition(it.toString()).getOrNull()
        }
        // get presentation definition from initTransaction as json string
        val requestPresentationDefinition = initTransaction.presentationDefinition

        assertEquals(
            requestPresentationDefinition,
            responsePresentationDefinition,
        ) { "presentationDefinition of response is not equal to presentationDefinition of request" }
    }
}
