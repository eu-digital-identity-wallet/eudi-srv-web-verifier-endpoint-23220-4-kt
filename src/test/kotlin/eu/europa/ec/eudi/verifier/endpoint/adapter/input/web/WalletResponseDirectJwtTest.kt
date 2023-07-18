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
import kotlinx.coroutines.runBlocking
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
        "verifier.clientMetadata.authorizationEncryptedResponseEnc=A128CBC-HS256",
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
     *
     * @see: <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw">OpenId4vp Response Mode "direct_post.jwt"</a>
     */
    @Test
    @Order(value = 1)
    fun `get request object, confirm headers`(): Unit = runBlocking {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("02-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        val requestObjectJsonResponse =
            WalletApiClient.getRequestObjectJsonResponse(client, transactionInitialized.requestUri!!)

//        val ecPublicKey = WalletApiClient.getEcKey(requestObjectJsonResponse)

        Assertions.assertEquals(
            "",
            requestObjectJsonResponse.getJSONObject("client_metadata").getString("authorization_signed_response_alg"),
            "authorization_signed_response_alg is not empty",
        )
        Assertions.assertEquals(
            "ECDH-ES",
            requestObjectJsonResponse.getJSONObject("client_metadata").getString("authorization_encrypted_response_alg"),
            "authorization_encrypted_response_alg is not ECDH-ES",
        )
        Assertions.assertEquals(
            requestObjectJsonResponse.getJSONObject("client_metadata").getString("authorization_encrypted_response_enc"),
            "A128CBC-HS256",
            "authorization_encrypted_response_enc is not A128CBC-HS256",
        )
        Assertions.assertTrue(requestObjectContainsClientMetadataEcKey(requestObjectJsonResponse)) { "jwks does not contain EC key" }
    }
    private fun requestObjectContainsClientMetadataEcKey(requestObjectJsonResponse: JSONObject): Boolean {
        var containsEcKey = false
        val jsonArray =
            requestObjectJsonResponse.getJSONObject("client_metadata").getJSONObject("jwks").getJSONArray("keys")
        for (i in 0 until jsonArray.length()) {
            val item = jsonArray.get(i)
            if (item is JSONObject) {
                if (item.getString("kty") == "EC") {
                    containsEcKey = true
                }
            }
        }
        return containsEcKey
    }
}
