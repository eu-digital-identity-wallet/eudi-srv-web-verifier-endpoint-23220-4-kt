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
@file:Suppress("invisible_reference", "invisible_member")

package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationExchange
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption
import eu.europa.ec.eudi.verifier.endpoint.domain.EphemeralEncryptionKeyPairJWK
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import net.minidev.json.JSONObject
import java.net.URL
import java.util.*
import kotlin.test.*

class SignRequestObjectNimbusTest {

    private val signRequestObject = TestContext.singRequestObject
    private val verifier = TestContext.singRequestObjectVerifier
    private val clientMetaData = TestContext.clientMetaData
    private val verifierId = TestContext.verifierId

    @Test
    fun `given a request object, it should be signed and decoded`() {
        val requestObject = RequestObject(
            verifierId = verifierId,
            responseType = listOf("vp_token", "id_token"),
            presentationDefinitionUri = null,
            presentationDefinition = PresentationExchange.jsonParser.decodePresentationDefinition(pd).getOrThrow(),
            scope = listOf("openid"),
            idTokenType = listOf("subject_signed_id_token"),
            nonce = UUID.randomUUID().toString(),
            responseMode = "direct_post.jwt",
            responseUri = URL("https://foo"),
            state = TestContext.testRequestId.value,
            aud = emptyList(),
            issuedAt = TestContext.testClock.instant(),
        )

        // responseMode is direct_post.jwt, so we need to generate an ephemeral key
        val ecKeyGenerator = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID(UUID.randomUUID().toString())
        val ecPublicKey = EphemeralEncryptionKeyPairJWK.from(ecKeyGenerator.generate())

        val jwt = signRequestObject.sign(RequestId("r"), clientMetaData, ecPublicKey, requestObject)
            .getOrThrow()
            .also { println(it) }
        val signedJwt = decode(jwt).getOrThrow().also { println(it) }
        assertX5cHeaderClaimDoesNotContainPEM(signedJwt.header)
        val claimSet = signedJwt.jwtClaimsSet
        assertEqualsRequestObjectJWTClaimSet(requestObject, claimSet)

        if (clientMetaData.jwkOption == EmbedOption.ByValue) {
            assertTrue { claimSet.claims.containsKey("client_metadata") }
            val clientMetadata = OIDCClientMetadata.parse(JSONObject(claimSet.getJSONObjectClaim("client_metadata")))
            assertNull(clientMetadata.jwkSetURI)
            assertEquals(JWKSet(ecPublicKey.jwk()).toPublicJWKSet(), clientMetadata.jwkSet)
        }
    }

    private fun decode(jwt: String): Result<SignedJWT> {
        return runCatching {
            val signedJWT = SignedJWT.parse(jwt)
            signedJWT.verify(verifier)
            signedJWT
        }
    }

    private fun assertEqualsRequestObjectJWTClaimSet(r: RequestObject, c: JWTClaimsSet) {
        assertEquals(r.verifierId.clientId, c.getStringClaim("client_id"))
        assertEquals(r.responseType.joinToString(separator = " "), c.getStringClaim("response_type"))
        assertEquals(r.presentationDefinitionUri?.toExternalForm(), c.getStringClaim("presentation_definition_uri"))
        assertEquals(r.presentationDefinition, c.getJSONObjectClaim("presentation_definition"))
        assertEquals(r.scope.joinToString(separator = " "), c.getStringClaim("scope"))
        assertEquals(r.idTokenType.joinToString(separator = " "), c.getStringClaim("id_token_type"))
        assertEquals(r.nonce, c.getStringClaim("nonce"))
        assertEquals(r.responseMode, c.getStringClaim("response_mode"))
        assertEquals(r.responseUri?.toExternalForm(), c.getStringClaim("response_uri"))
        assertEquals(r.state, c.getStringClaim("state"))
    }

    private fun assertX5cHeaderClaimDoesNotContainPEM(header: JWSHeader) {
        val chain = assertNotNull(header.x509CertChain?.toNonEmptyListOrNull())
        chain.forEach {
            // Ensure it is not a base64 encoded PEM
            assertNull(X509CertUtils.parse(it.decodeToString()))

            // Ensure it is a base64 encoded DER
            assertNotNull(X509CertUtils.parse(it.decode()))
        }
    }

    private fun assertEquals(pd: PresentationDefinition?, c: MutableMap<String, Any?>?) {
        val pd2 = c?.let { PresentationDefinitionJackson.fromJsonObject(c).getOrThrow() }
        assertEquals(pd, pd2)
    }

    private val pd = """
        {
  "type": "vp_token id_token",
  "id_token_type": "subject_signed_id_token",
  "presentation_definition": {
    "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
    "input_descriptors": [
      {
        "id": "wa_driver_license",
        "name": "Washington State Business License",
        "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
        "constraints": {
          "fields": [
            {
              "path": [
                "${'$'}.credentialSubject.dateOfBirth",
                "${'$'}.credentialSubject.dob",
                "${'$'}.vc.credentialSubject.dateOfBirth",
                "${'$'}.vc.credentialSubject.dob"
              ]
            }
          ]
        }
      }
    ]
  }
}
"""
}
