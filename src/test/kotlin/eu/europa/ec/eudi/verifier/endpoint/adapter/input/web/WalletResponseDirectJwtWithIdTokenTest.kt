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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestMethodOrder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.core.annotation.Order
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import java.time.Instant
import java.util.Date

@Deprecated(message = "direct_post.jwt no longer supports jwt (not encoded)")
@Disabled
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.response.mode=DirectPostJwt",
        "verifier.clientMetadata.authorizationSignedResponseAlg=",
        "verifier.clientMetadata.authorizationEncryptedResponseAlg=ECDH-ES",
        "verifier.clientMetadata.authorizationEncryptedResponseEnc=A128CBC-HS256",
    ],
)
@TestMethodOrder(OrderAnnotation::class)
@AutoConfigureWebTestClient(timeout = Integer.MAX_VALUE.toString()) // used for debugging only
internal class WalletResponseDirectJwtWithIdTokenTest {

    @Autowired
    private lateinit var client: WebTestClient

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response, an idToken
     *
     * @see: <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw">OpenId4vp Response Mode "direct_post.jwt"</a>
     */
    @Test
    @Order(value = 1)
    fun `post wallet response jwt of an idToken`(): Unit = runBlocking {
        // given
        val idToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImF1ZCI6InlvdSIs"
        val initTransaction = VerifierApiClient.loadInitTransactionTO("01-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        // create a JWT with the idToken
        val jwt = jwtForIdToken(requestId.value, idToken)

        // create a post form url encoded body
        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("response", jwt)

        // when
        WalletApiClient.directPostJwt(client, formEncodedBody)
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post request for id_token
     * - wallet to verifier backend, to get request
     * - wallet to verifier backend, to post wallet response, an idToken
     * - verifier to verifier backend, to get the wallet response
     *
     */
    @Test
    @Order(value = 2)
    fun `get wallet response jwt of an idToken`(): Unit = runBlocking {
        // given
        val idToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImF1ZCI6InlvdSIs"
        val initTransaction = VerifierApiClient.loadInitTransactionTO("01-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        // create a JWT with the idToken
        val jwt = jwtForIdToken(requestId.value, idToken)

        // create a post form url encoded body
        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("response", jwt)
        formEncodedBody.add("state", requestId.value)
        // send the wallet response
        WalletApiClient.directPostJwt(client, formEncodedBody)

        // when
        val response = VerifierApiClient.getWalletResponse(
            client,
            PresentationId(transactionInitialized.presentationId),
            Nonce(initTransaction.nonce!!),
        )
        println("response: $response")
        val walletResponse = decodeWalletResponseBody(response)

        // then
        Assertions.assertNotNull(response, "response is null")
        Assertions.assertEquals(idToken, walletResponse?.idToken, "unexpected response.id_token")
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response, an error
     *
     * @see: <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-error-response">OpenId4vp, Error Response</a>
     */
    @Test
    @Order(value = 3)
    fun `post wallet response jwt of an error`(): Unit = runBlocking {
        // given
        val error = "invalid_request"
        val errorDescription =
            "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more " +
                "than once, or is otherwise malformed."
        val initTransaction = VerifierApiClient.loadInitTransactionTO("01-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        // create a JWT with the error and error_description
        val jwt = jwtForError(requestId.value, error, errorDescription)

        // create a post form url encoded body
        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("response", jwt)

        // when
        WalletApiClient.directPostJwt(client, formEncodedBody)
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response, an error
     * - verifier to verifier backend, to get the wallet response (the error)
     *
     * @see: <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-error-response">OpenId4vp, Error Response</a>
     */
    @Test
    @Order(value = 4)
    fun `get wallet response jwt of an error`(): Unit = runBlocking {
        // given
        val error = "invalid_request"
        val errorDescription =
            "The request is missing a required parameter, includes an invalid parameter value, " +
                "includes a parameter more than once, or is otherwise malformed."
        val initTransaction = VerifierApiClient.loadInitTransactionTO("01-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        // create a JWT with the error and error_description
        val jwt = jwtForError(requestId.value, error, errorDescription)

        // create a post form url encoded body
        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("response", jwt)
        // send the wallet response
        WalletApiClient.directPostJwt(client, formEncodedBody)

        // when
        val response = VerifierApiClient.getWalletResponse(
            client,
            PresentationId(transactionInitialized.presentationId),
            Nonce(initTransaction.nonce!!),
        )
        println("response: $response")
        val walletResponse = decodeWalletResponseBody(response)

        // then
        Assertions.assertNotNull(response, "response is null")
        Assertions.assertEquals(error, walletResponse?.error, "unexpected response.error")
        Assertions.assertEquals(errorDescription, walletResponse?.errorDescription, "unexpected response.errorDescription")
    }

    /*
     * decode WalletResponseTO from String
     */
    fun decodeWalletResponseBody(walletResponse: String): WalletResponseTO? = runBlocking {
        Json.decodeFromString<WalletResponseTO>(walletResponse)
    }

    /*
     * create a JWT for the idToken
     *
     * @see: <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw">OpenId4vp</a>
     */
    fun jwtForIdToken(state: String, idToken: String) = runBlocking {
        val key: ECKey = ECKeyGenerator(Curve.P_256)
            .keyID("123")
            .generate()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(key.keyID)
            .build()
        val payload = JWTClaimsSet.Builder()
            .issuer("issuer value")
            .audience("https://client.example.org/cb") // client_id tou verifier, get the env variable
            .expirationTime(Date.from(Instant.now().plusSeconds(120)))
            .claim("state", state)
            .claim("id_token", idToken)
            .build()
        val signedJWT = SignedJWT(header, payload)
        signedJWT.sign(ECDSASigner(key.toECPrivateKey()))
        signedJWT.serialize()
    }

    /*
     * create a JWT for the error
     *
     * @see: <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw">OpenId4vp</a>
     */
    fun jwtForError(state: String, error: String, errorDescription: String) = runBlocking {
        val key: ECKey = ECKeyGenerator(Curve.P_256)
            .keyID("123")
            .generate()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(key.keyID)
            .build()
        val payload = JWTClaimsSet.Builder()
            .issuer("issuer value")
            .audience("https://client.example.org/cb")
            .expirationTime(Date.from(Instant.now().plusSeconds(120)))
            .claim("state", state)
            .claim("error", error)
            .claim("error_description", errorDescription)
            .build()
        val signedJWT = SignedJWT(header, payload)
        signedJWT.sign(ECDSASigner(key.toECPrivateKey()))
        signedJWT.serialize()
    }
}
