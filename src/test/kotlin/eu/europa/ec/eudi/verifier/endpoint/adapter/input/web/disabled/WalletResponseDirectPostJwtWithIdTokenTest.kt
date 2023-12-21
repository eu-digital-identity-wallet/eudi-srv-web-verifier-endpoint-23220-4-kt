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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.disabled

import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.TestUtils
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApi
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.WalletApi
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import org.json.JSONObject
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestMethodOrder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import org.springframework.web.reactive.function.BodyInserters

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(OrderAnnotation::class)
@AutoConfigureWebTestClient(timeout = Integer.MAX_VALUE.toString()) // used for debugging only
@Disabled
internal class WalletResponseDirectPostJwtWithIdTokenTest {

    @Autowired
    private lateinit var client: WebTestClient

    /**
     * OpenId4VP draft 18, section 10.5, Figure 3:
     * - (request) Verifier to Verifier Response endpoint, flow "(2) initiate transaction"
     * - (response) Verifier ResponseEndpoint to Verifier, flow "(3) return transaction-id & request-id"
     */
    fun `Verifier to VerifierBackend - sends HTTP POST presentation definition, return requestUri`(): String {
        // given
        val presentationDefinitionBody = TestUtils.loadResource("01-presentationDefinition.json")
        println("presentationDefinitionBody=$presentationDefinitionBody")
        // when / then
        val requestUri = client.post().uri(VerifierApi.INIT_TRANSACTION_PATH)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(presentationDefinitionBody))
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult()
            .responseBodyContent?.let { JSONObject(String(it)).get("request_uri").toString() }
        println("requestUri=$requestUri")

        Assertions.assertNotNull(requestUri)

        return requestUri!!
    }

    /**
     *
     * ISO 23220-4, Appendix B:
     * - (request) mDocApp to Internet Web Service, flow "6 HTTPs GET to request_uri"
     * - (response) Internet Web Service to mDocApp, flow "7 JWS Authorisation request object [section B.3.2.1]"
     */
    fun `Wallet to VerifierBackend - sends HTTP GET requestUri to retrieve presentation definition, return presentationId`(
        requestUri: String,
    ): String {
        // given

        // when / then

        // update the request_uri to point to the local server
        val relativeRequestUri = requestUri.removePrefix("http://localhost:0")
        println("relative request_uri: $relativeRequestUri")

        // get the presentation definition
        val getResponse = client.get()
            .uri(relativeRequestUri)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult()

        Assertions.assertNotNull(getResponse.responseBodyContent, "responseBodyContent is empty")

        val getResponseString = String(getResponse.responseBodyContent!!)
        Assertions.assertNotNull(getResponseString, "getResponseString is null")

        println("response: $getResponseString")

        val (_, payload) = TestUtils.parseJWTIntoClaims(getResponseString)

        val presentationId = payload["nonce"]!!.jsonPrimitive.contentOrNull
        println("presentationId: $presentationId")

        Assertions.assertNotNull(presentationId)

        return presentationId!!
    }

    /**
     * OpenId4VP draft 18, section 10.5, Figure 3:
     * - (request) Wallet to Verifier Response endpoint, flow "(5) Authorisation Response (VP Token, state)"
     * - (response) Verifier ResponseEndpoint to Wallet, flow "(6) Response (redirect_uri with response_code)"
     *
     * ISO 23220-4, Appendix B:
     * - (request) mDocApp to Internet Web Service, flow "12 HTTPs POST to response_uri [section B.3.2.2]
     * - (response) Internet Web Service to mDocApp, flow "14 OK: HTTP 200 with redirect_uri"
     */
    fun `Wallet to VerifierBackend - sends HTTP POST to submit wallet response, return presentationId`(): String {
        // given
        val requestUri = `Verifier to VerifierBackend - sends HTTP POST presentation definition, return requestUri`()
        val presentationId =
            `Wallet to VerifierBackend - sends HTTP GET requestUri to retrieve presentation definition, return presentationId`(requestUri)

        // when
        val requestId = requestUri.removePrefix("http://localhost:0/wallet/request.jwt/")

        val walletResponseBody = """
            {
              "state": "$requestId",
              "id_token": "12345"
            }
        """

        client.post().uri(WalletApi.walletResponsePath)
            .contentType(MediaType.APPLICATION_JSON)
            // .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(walletResponseBody))
            .exchange()
            // then
            .expectStatus().isOk()

        return presentationId
    }

//    @Test @Order(value = 1)
//    fun `post wallet response - confirm returns 200`(): Unit = runBlocking {
//        val presentationId = `Wallet to VerifierBackend sends HTTP POST to submit wallet response, return presentationId`()
//        Assertions.assertNotNull(presentationId)
//    }
    @Test
    @Order(value = 1)
    fun `post wallet response (only idToken) - confirm returns 200`(): Unit = runBlocking {
        val presentationId = `Wallet to VerifierBackend - sends HTTP POST to submit wallet response, return presentationId`()
        Assertions.assertNotNull(presentationId)
    }

    /**
     * OpenId4VP draft 18, section 10.5, Figure 3:
     * - (request) Verifier to Verifier Response endpoint, flow "(8) fetch response data (transaction-id, response_code)"
     * - (response) Verifier ResponseEndpoint to Verifier, flow "(9) response data (VP Token, Presentation Submission)"
     *
     * ISO 23220-4, Appendix B:
     * - (request) mdocVerification application Internet frontend to Internet Web Service, flow "18 HTTPs POST to response_uri [section B.3.2.2]
     * - (response) Internet Web Service to mdocVerification application Internet frontend, flow "20 return status and conditionally return data"
     */
    @Test
    @Order(value = 2)
    fun `get authorisation response - confirm returns 200`(): Unit = runBlocking {
        // given: the wallet response has been posted
        val presentationId = `Wallet to VerifierBackend - sends HTTP POST to submit wallet response, return presentationId`()
        Assertions.assertNotNull(presentationId)

        // when: the wallet response is retrieved
        val requestUri = VerifierApi.WALLET_RESPONSE_PATH.replace("{presentationId}", presentationId)

        val responseSpec = client.get().uri(requestUri)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
        val returnResult = responseSpec.expectBody<JsonObject>().returnResult()
        returnResult.status.also { println("response status: $it") }
        returnResult.responseHeaders.also { println("response headers: $it") }
        returnResult.responseBody?.also { jsonResponse ->
            TestUtils.prettyPrintJson("response body content:\n", jsonResponse)
        }

        // then
        Assertions.assertEquals(returnResult.status, HttpStatus.OK)
    }
}
