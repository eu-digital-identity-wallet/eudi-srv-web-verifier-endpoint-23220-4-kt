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

import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.json.JSONObject
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
internal class PresentationDefinitionTest() {

    @Autowired
    private lateinit var client: WebTestClient

    @Test
    fun `post presentation definition returns 200`() {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("00-presentationDefinition.json")
        println("initTransaction: $initTransaction")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        println("transactionInitialized: $transactionInitialized")
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        println("requestId: ${requestId.value}")
    }

    @Test
    fun `get presentation definition returns 200`() {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("00-presentationDefinition.json")
        println("initTransaction: $initTransaction")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        println("transactionInitialized: $transactionInitialized")
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        println("requestId: ${requestId.value}")

        val relativeRequestUri =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0")!!)
        println("relativeRequestUri: $relativeRequestUri")

        // then
        val getResponse = client.get().uri(relativeRequestUri.value)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult()
        val getResponseString = String(getResponse.responseBodyContent!!)
        println("response: $getResponseString")

        val (header, payload) = TestUtils.parseJWT(getResponseString)
        // debug
        val prettyHeader = TestUtils.prettyPrintJson(header)
        val prettyPayload = TestUtils.prettyPrintJson(payload)
        println("prettyHeader:\n$prettyHeader")
        println("prettyPayload:\n$prettyPayload")

        val responsePresentationDefinition = JSONObject(payload).get("presentation_definition")
        // get presentation definition from initTransaction as json string
        val requestPresentationDefinition = Json.encodeToString(initTransaction.presentationDefinition)

        assert(
            TestUtils.compareJsonStrings(
                requestPresentationDefinition,
                responsePresentationDefinition.toString(),
            ),
            { "presentationDefinition of response is not equal to presentationDefinition of request" },
        )
    }
}
