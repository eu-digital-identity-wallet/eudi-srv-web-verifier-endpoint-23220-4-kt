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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.json.JSONObject
import org.junit.jupiter.api.Assertions
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
import java.util.*

/*
  https://jira.intrasoft-intl.com/browse/EUDIW-693
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(
    properties = [
        "verifier.maxAge=PT6400M",
        "verifier.response.mode=DirectPostJwt",
        "verifier.clientMetadata.authorizationSignedResponseAlg=",
        "verifier.clientMetadata.authorizationEncryptedResponseAlg=ECDH-ES",
        "verifier.clientMetadata.authorizationEncryptedResponseEnc=A256GCM",
    ],
)
@TestMethodOrder(OrderAnnotation::class)
@AutoConfigureWebTestClient(timeout = Integer.MAX_VALUE.toString()) // used for debugging only
internal class WalletResponseDirectJwtTest {

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
    fun `direct_post_jwt vp_token end to end`(): Unit = runBlocking {
        // given
        val idToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImF1ZCI6InlvdSIs"
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId = RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val requestObjectJsonResponse =
            WalletApiClient.getRequestObjectJsonResponse(client, transactionInitialized.requestUri!!)

        val signAlg =
            requestObjectJsonResponse.getJSONObject("client_metadata").getString("authorization_signed_response_alg")
        Assertions.assertEquals("", signAlg, "authorization_signed_response_alg is not empty")
        val encAlg =
            requestObjectJsonResponse.getJSONObject("client_metadata").getString("authorization_encrypted_response_alg")
        Assertions.assertEquals("ECDH-ES", encAlg, "authorization_encrypted_response_alg is not ECDH-ES")
        val encMethod = requestObjectJsonResponse.getJSONObject("client_metadata")
            .getString("authorization_encrypted_response_enc")
        Assertions.assertEquals(encMethod, "A256GCM", "authorization_encrypted_response_enc is not A256GCM")

        val clientMetadataEcKey =
            requestObjectClientMetadataEcKey(requestObjectJsonResponse)
        Assertions.assertNotNull(clientMetadataEcKey) { "jwks does not contain EC key" }

        val jweAlgorithm = JWEAlgorithm.parse(encAlg)
        val encryptMethod = EncryptionMethod.parse(encMethod)

        val ecKey = ECKey.parse(clientMetadataEcKey)

        // (wallet) generate JWT with claims
        val now = Date()
        val jwtClaims: JWTClaimsSet = JWTClaimsSet.Builder()
            .issuer("Verifier")
            .audience(Arrays.asList("https://eudi.com", "https://eudi.org"))
            .expirationTime(Date(now.getTime() + 1000 * 60 * 10)) // expires in 10 minutes
            .notBeforeTime(now)
            .issueTime(now)
            .jwtID(UUID.randomUUID().toString())
            .claim("state", requestId.value)
            .claim("id_token", idToken)
            .claim("vp_token", TestUtils.loadResource("02-vpToken.json"))
            .claim("presentation_submission", TestUtils.loadResource("02-presentationSubmission.json"))
            .build()
        println("plaintextJwtClaims: ${jwtClaims.toJSONObject()}")

        // Request JWT encrypted with ECDH-ES
        val jweHeader = JWEHeader(jweAlgorithm, encryptMethod)
        println("header = ${jweHeader.toJSONObject()}")

        // Create the encrypted JWT object
        val encryptedJWT = EncryptedJWT(jweHeader, jwtClaims)

        // Create an encrypter with the specified public EC key
        val encrypter: JWEEncrypter = ECDHEncrypter(ecKey)

        // Do the actual encryption
        encryptedJWT.encrypt(encrypter)

        // Serialise to JWT compact form
        val jwtString: String = encryptedJWT.serialize()
        println("jwtString = $jwtString")

        // create a post form url encoded body
        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("response", jwtString)
        formEncodedBody.add("state", requestId.value)
        // send the wallet response
        WalletApiClient.directPostJwt(client, formEncodedBody)

        // when
        val response = VerifierApiClient.getWalletResponse(
            client,
            PresentationId(transactionInitialized.presentationId),
            Nonce(initTransaction.nonce!!),
        )
        println("Verifier retrieves the wallet response: $response")
        val walletResponse = decodeWalletResponseBody(response)
        println("wallet response to domain: $walletResponse")

        // then
        Assertions.assertNotNull(response, "response is null")
    }

    private fun requestObjectClientMetadataEcKey(requestObjectJsonResponse: JSONObject): String? {
        val jsonArray =
            requestObjectJsonResponse.getJSONObject("client_metadata").getJSONObject("jwks").getJSONArray("keys")
        for (i in 0 until jsonArray.length()) {
            val item = jsonArray.get(i)
            if (item is JSONObject) {
                if (item.getString("kty") == "EC") {
                    return item.toString()
                }
            }
        }
        return null
    }

    /*
     * decode WalletResponseTO from String
     */
    fun decodeWalletResponseBody(walletResponse: String): WalletResponseTO? = runBlocking {
        Json.decodeFromString<WalletResponseTO>(walletResponse)
    }
}
