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

import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.nimbusEnc
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.nimbusJWSAlgorithm
import eu.europa.ec.eudi.verifier.endpoint.domain.JarmOption
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.ResponseModeTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
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

/*
  https://jira.intrasoft-intl.com/browse/EUDIW-693
 */
@VerifierApplicationTest
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.response.mode=DirectPostJwt",
        "verifier.clientMetadata.authorizationSignedResponseAlg=",
        "verifier.clientMetadata.authorizationEncryptedResponseAlg=ECDH-ES",
        "verifier.clientMetadata.authorizationEncryptedResponseEnc=A256GCM",
        "verifier.jwk.embed=ByValue",
    ],
)
@TestMethodOrder(OrderAnnotation::class)
@AutoConfigureWebTestClient(timeout = Integer.MAX_VALUE.toString()) // used for debugging only
internal class WalletResponseDirectPostJwtTest {

    private val log: Logger = LoggerFactory.getLogger(WalletResponseDirectPostJwtTest::class.java)

    @Autowired
    private lateinit var client: WebTestClient

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response, an idToken
     * - verifier to verifier backend, to get wallet response
     *
     * @see: <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw">OpenId4vp Response Mode "direct_post.jwt"</a>
     */
    @Test
    @Order(value = 1)
    fun `direct_post_jwt vp_token end to end`() = runTest {
        fun test(
            presentationDefinition: String,
            presentationSubmission: String,
            vpToken: String,
            asserter: (WalletResponseTO) -> Unit,
        ) {
            // given
            val idToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImF1ZCI6InlvdSIs"
            val initTransaction = VerifierApiClient.loadInitTransactionTO(presentationDefinition)
            val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
            val requestId =
                RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
            val requestObjectJsonResponse =
                WalletApiClient.getRequestObjectJsonResponse(client, transactionInitialized.requestUri!!)

            val jarmOption = assertIs<JarmOption.Encrypted>(requestObjectJsonResponse.jarmOption())
            val ecKey = requestObjectJsonResponse.ecKey()
            assertEquals(JarmOption.Encrypted("ECDH-ES", "A256GCM"), jarmOption)
            assertNotNull(ecKey)

            // (wallet) generate JWT with claims
            val pd: JsonElement = Json.decodeFromString(TestUtils.loadResource(presentationSubmission))
            val jwtClaims: JWTClaimsSet = buildJsonObject {
                put("state", requestId.value)
                put("id_token", idToken)
                put("vp_token", Json.decodeFromString(TestUtils.loadResource(vpToken)))
                put("presentation_submission", pd)
            }.run { JWTClaimsSet.parse(Json.encodeToString(this)) }

            log.info("plaintextJwtClaims: ${jwtClaims.toJSONObject()}")

            // Request JWT encrypted with ECDH-ES
            val jweHeader = JWEHeader(jarmOption.nimbusJWSAlgorithm(), jarmOption.nimbusEnc())
            log.info("header = ${jweHeader.toJSONObject()}")

            // Create the encrypted JWT object
            val encryptedJWT = EncryptedJWT(jweHeader, jwtClaims)

            // Create an encrypter with the specified public EC key
            val encrypter: JWEEncrypter = ECDHEncrypter(ecKey)

            // Do the actual encryption
            encryptedJWT.encrypt(encrypter)

            // Serialise to JWT compact form
            val jwtString: String = encryptedJWT.serialize()
            log.info("jwtString = $jwtString")

            // create a post form url encoded body
            val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
            formEncodedBody.add("response", jwtString)
            formEncodedBody.add("state", requestId.value)

            // send the wallet response
            WalletApiClient.directPostJwt(client, formEncodedBody)

            // when
            val response = VerifierApiClient.getWalletResponse(
                client,
                TransactionId(transactionInitialized.transactionId),
            )
            // then
            assertNotNull(response, "response is null")
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
     * Verifies that a Transaction expecting a direct_post.jwt Wallet response, doesn't accept a direct_post Wallet response.
     */
    @Test
    @Order(value = 2)
    fun `with response_mode direct_post_jwt, direct_post wallet responses are rejected`(): Unit = runBlocking {
        // given
        val idToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImF1ZCI6InlvdSIs"
        val initTransaction = VerifierApiClient.loadInitTransactionTO(
            "02-presentationDefinition.json",
        ).copy(responseMode = ResponseModeTO.DirectPostJwt)
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val requestObjectJsonResponse =
            WalletApiClient.getRequestObjectJsonResponse(client, transactionInitialized.requestUri!!)

        val jarmOption = assertIs<JarmOption.Encrypted>(requestObjectJsonResponse.jarmOption())
        val ecKey = requestObjectJsonResponse.ecKey()
        assertEquals(JarmOption.Encrypted("ECDH-ES", "A256GCM"), jarmOption)
        assertNotNull(ecKey)

        // (wallet)
        // create a post form url encoded body
        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", idToken)
        formEncodedBody.add("vp_token", TestUtils.loadResource("02-vpToken.json"))
        formEncodedBody.add("presentation_submission", TestUtils.loadResource("02-presentationSubmission.json"))

        // send the wallet response
        // we expect the response submission to fail
        try {
            WalletApiClient.directPost(client, formEncodedBody)
            fail("Expected direct_post submission to fail for direct_post.jwt Presentation")
        } catch (error: AssertionError) {
            assertEquals("Status expected:<200 OK> but was:<400 BAD_REQUEST>", error.message)
        }
    }
}
