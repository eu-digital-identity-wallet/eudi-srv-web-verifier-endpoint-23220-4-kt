package eu.europa.ec.euidw.verifier.adapter.out.jose

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.prex.PresentationExchange
import eu.europa.ec.euidw.verifier.TestContext
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.URL
import java.net.URLEncoder
import java.util.*


class SignRequestObjectNimbusTest {

    private val signRequestObject = TestContext.singRequestObject
    private val verifier = TestContext.singRequestObjectVerifier
    private val clientMetaData = TestContext.clientMetaData

    @Test
    fun `given a request object, it should be signed and decoded`() {


        val requestObject = RequestObject(
            clientId = "client-id",
            clientIdScheme = "pre-registered",
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
            issuedAt = TestContext.testClock.instant()

        )

        val jwt = signRequestObject.sign(clientMetaData,requestObject).getOrThrow().also { println(it) }
        val claimSet = decode(jwt).getOrThrow().also { println(it) }

        assertEqualsRequestObjectJWTClaimSet(requestObject, claimSet)
    }

    private fun decode(jwt: String): Result<JWTClaimsSet> {

        return runCatching {
            val signedJWT = SignedJWT.parse(jwt)
            signedJWT.verify(verifier)
            signedJWT.jwtClaimsSet
        }
    }

    private fun assertEqualsRequestObjectJWTClaimSet(r: RequestObject, c: JWTClaimsSet) {

        assertEquals(r.clientId, c.getStringClaim("client_id"))
        assertEquals(r.clientIdScheme, c.getStringClaim("client_id_scheme"))
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

    private fun assertEquals(pd: PresentationDefinition?, c: MutableMap<String, Any?>?) {

        val pd2 = c?.let { PresentationDefinitionJackson.fromJsonObject(c).getOrThrow() }
        assertTrue(pd == pd2)

    }


    val pd = """{
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
}"""
}