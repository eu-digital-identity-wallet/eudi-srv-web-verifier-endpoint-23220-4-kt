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
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseCode
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.IdTokenTypeTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.PresentationTypeTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseAcceptedTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation
import org.junit.jupiter.api.TestMethodOrder
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

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
internal class WalletResponseDirectPostWithIdTokenTest {

    private val log: Logger = LoggerFactory.getLogger(WalletResponseDirectPostWithIdTokenTest::class.java)

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
        val initTransaction = VerifierApiClient.loadInitTransactionTO("01-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")

        // when
        WalletApiClient.directPost(client, formEncodedBody)
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
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("01-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri!!.removePrefix("http://localhost:0/wallet/request.jwt/"))
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")

        WalletApiClient.directPost(client, formEncodedBody)

        // when
        val response = VerifierApiClient.getWalletResponse(
            client,
            TransactionId(transactionInitialized.transactionId),
        )

        // then
        assertNotNull(response)
    }

    @Test
    @Order(value = 3)
    fun `when method to get wallet response is REDIRECT then response should contain a valid redirect_uri`() = runTest {
        val initTransaction = InitTransactionTO(
            PresentationTypeTO.IdTokenRequest,
            IdTokenTypeTO.SubjectSigned,
            null,
            null,
            "nonce",
            redirectUriTemplate =
                "https://client.example.org/cb#response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
        )
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")

        WalletApiClient.directPost(
            client,
            formEncodedBody,
            { responseSpec ->
                val returnResult = responseSpec
                    .expectBody<WalletResponseAcceptedTO>()
                    .returnResult()
                    .responseBody
                val uri = URI.create(returnResult!!.redirectUri)
                assertTrue { uri.scheme == "https" }
                assertTrue { uri.host == "client.example.org" }
                assertTrue { uri.fragment.contains("response_code") }
            },
        )
    }

    @Test
    @Order(value = 4)
    fun `when method to get wallet response does not require response_code and code is provided, BAD_REQUEST is responded`() = runTest {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("01-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri!!.removePrefix("http://localhost:0/wallet/request.jwt/"))
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")

        WalletApiClient.directPost(client, formEncodedBody)

        // when
        val returnResult = VerifierApiClient.getWalletResponseNoValidation(
            client,
            TransactionId(transactionInitialized.transactionId),
            ResponseCode("yszZvb3IoEnSYcRI7R7xZ01_n59AvhBTdr71uSCaqDaT7kF32spauGdn3KRHg0NiR2qtxA5_JeA4xd-Tu6oqhQ"),
        )

        // then
        Assertions.assertEquals(HttpStatus.BAD_REQUEST, returnResult.status)
    }

    @Test
    @Order(value = 5)
    fun `when method to get wallet response does require response_code and no code is provided, BAD_REQUEST is responded`() = runTest {
        // given
        val initTransaction = InitTransactionTO(
            PresentationTypeTO.IdTokenRequest,
            IdTokenTypeTO.SubjectSigned,
            null,
            null,
            "nonce",
            redirectUriTemplate =
                "https://client.example.org/cb#response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
        )
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri!!.removePrefix("http://localhost:0/wallet/request.jwt/"))
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")

        WalletApiClient.directPost(client, formEncodedBody)

        // when
        val returnResult = VerifierApiClient.getWalletResponseNoValidation(
            client,
            TransactionId(transactionInitialized.transactionId),
        )

        // then
        Assertions.assertEquals(HttpStatus.BAD_REQUEST, returnResult.status)
    }

    @Test
    @Order(value = 6)
    fun `when method to get wallet response does require response_code and code is provided, wallet response is returned`() = runTest {
        // given
        val initTransaction = InitTransactionTO(
            PresentationTypeTO.IdTokenRequest,
            IdTokenTypeTO.SubjectSigned,
            null,
            null,
            "nonce",
            redirectUriTemplate =
                "https://client.example.org/cb#response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
        )
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri!!.removePrefix("http://localhost:0/wallet/request.jwt/"))
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")

        var responseCode: String? = null
        WalletApiClient.directPost(
            client,
            formEncodedBody,
            { responseSpec ->
                val returnResult = responseSpec
                    .expectBody<WalletResponseAcceptedTO>()
                    .returnResult()
                    .responseBody
                responseCode = returnResult?.redirectUri?.removePrefix("https://client.example.org/cb#response_code=")
            },
        )

        // when
        val response = VerifierApiClient.getWalletResponseNoValidation(
            client,
            TransactionId(transactionInitialized.transactionId),
            ResponseCode(responseCode!!),
        )

        // then
        assertNotNull(response, "response is null")
    }
}
