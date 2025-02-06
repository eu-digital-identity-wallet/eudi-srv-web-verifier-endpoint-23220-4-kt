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

import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation
import org.junit.jupiter.api.TestMethodOrder
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.core.annotation.Order
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import kotlin.test.*

@VerifierApplicationTest
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.response.mode=DirectPost",
        "verifier.clientMetadata.authorizationSignedResponseAlg=",
        "verifier.clientMetadata.authorizationEncryptedResponseAlg=ECDH-ES",
        "verifier.clientMetadata.authorizationEncryptedResponseEnc=A128CBC-HS256",
    ],
)
@TestMethodOrder(OrderAnnotation::class)
@AutoConfigureWebTestClient(timeout = Integer.MAX_VALUE.toString()) // used for debugging only
internal class WalletResponseDirectPostWithIdTokenAndVpTokenTest {

    private val log: Logger = LoggerFactory.getLogger(WalletResponseDirectPostWithIdTokenAndVpTokenTest::class.java)

    @Autowired
    private lateinit var client: WebTestClient

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response
     */
    @Test
    @Order(value = 1)
    fun `post wallet response (only idToken) - confirm returns 200`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val presentationId = transactionInitialized.transactionId
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", TestUtils.loadResource("02-vpToken.json"))
        formEncodedBody.add("presentation_submission", TestUtils.loadResource("02-presentationSubmission.json"))

        // when
        WalletApiClient.directPost(client, requestId, formEncodedBody)

        // then
        assertNotNull(presentationId)
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response
     * - verifier to verifier backend, to get wallet response
     */
    @Test
    @Order(value = 2)
    fun `get authorisation response - confirm returns 200`() = runTest {
        suspend fun test(
            presentationDefinition: String,
            presentationSubmission: String,
            vpToken: String,
            asserter: (WalletResponseTO) -> Unit,
        ) {
            // given
            val initTransaction = VerifierApiClient.loadInitTransactionTO(presentationDefinition)
            val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
            val presentationId = TransactionId(transactionInitialized.transactionId)
            val requestId =
                RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
            WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

            val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
            formEncodedBody.add("state", requestId.value)
            formEncodedBody.add("id_token", "value 1")
            formEncodedBody.add("vp_token", TestUtils.loadResource(vpToken))
            formEncodedBody.add("presentation_submission", TestUtils.loadResource(presentationSubmission))

            WalletApiClient.directPost(client, requestId, formEncodedBody)

            // when
            val response = VerifierApiClient.getWalletResponse(client, presentationId)

            // then
            assertNotNull(response)
            asserter(response)
        }

        // Test with single Verifiable Presentation -- single JsonObject
        test("02-presentationDefinition.json", "02-presentationSubmission.json", "02-vpToken.json") {
            val vpToken = assertNotNull(it.vpToken)
            assertEquals(1, vpToken.size)
            assertIs<JsonObject>(vpToken[0])
        }

        // Test with multiple Verifiable Presentation -- single JsonArray that contains one JsonPrimitive and one JsonObject
        test("03-presentationDefinition.json", "03-presentationSubmission.json", "03-vpToken.json") {
            val vpToken = assertNotNull(it.vpToken)
            assertEquals(2, vpToken.size)
            assertIs<JsonPrimitive>(vpToken[0])
            assertIs<JsonObject>(vpToken[1])
        }
    }

    /**
     * Verifies that a Transaction expecting a direct_post Wallet response, doesn't accept a direct_post.jwt Wallet response.
     */
    @Test
    @Order(value = 3)
    fun `with response_mode direct_post, direct_post_jwt wallet responses are rejected`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        // At this point we don't generate an actual JARM response
        // The response will be rejected before JARM parsing/verification takes place
        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("response", "response")

        // send the wallet response
        // we expect the response submission to fail
        try {
            WalletApiClient.directPostJwt(client, requestId, formEncodedBody)
            fail("Expected direct_post.jwt submission to fail for direct_post Presentation")
        } catch (error: AssertionError) {
            assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
        }
    }

    @Test
    @Order(value = 4)
    fun `presentation with dcql query accepts dcql response`() = runTest {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("04-dcql.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val presentationId = TransactionId(transactionInitialized.transactionId)
        val requestId = RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", TestUtils.loadResource("04-vpToken.json"))

        WalletApiClient.directPost(client, requestId, formEncodedBody)

        val response = assertNotNull(VerifierApiClient.getWalletResponse(client, presentationId))

        val vpToken = assertNotNull(response.vpToken)
        assertEquals(2, vpToken.size)
        assertIs<JsonPrimitive>(vpToken[0])
        assertIs<JsonObject>(vpToken[1])
    }

    @Test
    @Order(value = 5)
    fun `presentation with presentation exchange query rejects dcql response`() = runTest {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("03-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId = RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", TestUtils.loadResource("04-vpToken.json"))

        try {
            WalletApiClient.directPost(client, requestId, formEncodedBody)
            fail("Expected DCQL response to be rejected for Presentation Exchange query")
        } catch (error: AssertionError) {
            assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
        }
    }

    @Test
    @Order(value = 6)
    fun `presentation with dcql query rejects presentation exchange response`() = runTest {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("04-dcql.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId = RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", TestUtils.loadResource("03-vpToken.json"))
        formEncodedBody.add("presentation_submission", TestUtils.loadResource("03-presentationSubmission.json"))

        try {
            WalletApiClient.directPost(client, requestId, formEncodedBody)
            fail("Expected Presentation Exchange response to be rejected for DCQL query")
        } catch (error: AssertionError) {
            assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
        }
    }

    @Test
    @Order(value = 7)
    fun `presentation with dcql query rejects dcql response when credential sets are not satisfied`() = runTest {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("05-dcql.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId = RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", TestUtils.loadResource("04-vpToken.json"))

        try {
            WalletApiClient.directPost(client, requestId, formEncodedBody)
            fail("Expected Presentation Exchange response to be rejected for DCQL query")
        } catch (error: AssertionError) {
            assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
        }
    }

    @Test
    @Order(value = 8)
    fun `presentation with dcql query accepts dcql response when all required credential sets are satisfied`() = runTest {
        val initTransaction = VerifierApiClient.loadInitTransactionTO("05-dcql.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val presentationId = TransactionId(transactionInitialized.transactionId)
        val requestId = RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")
        formEncodedBody.add("vp_token", TestUtils.loadResource("05-vpToken.json"))

        WalletApiClient.directPost(client, requestId, formEncodedBody)

        val response = assertNotNull(VerifierApiClient.getWalletResponse(client, presentationId))

        val vpToken = assertNotNull(response.vpToken)
        assertEquals(3, vpToken.size)
        assertIs<JsonPrimitive>(vpToken[0])
        assertIs<JsonObject>(vpToken[1])
        assertIs<JsonPrimitive>(vpToken[2])
    }
}
