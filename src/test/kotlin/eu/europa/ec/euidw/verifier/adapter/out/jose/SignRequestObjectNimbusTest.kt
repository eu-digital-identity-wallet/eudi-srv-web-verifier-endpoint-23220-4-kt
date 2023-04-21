package eu.europa.ec.euidw.verifier.adapter.out.jose

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.euidw.verifier.application.port.out.jose.RequestObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.URL
import java.net.URLEncoder
import java.util.*


class SignRequestObjectNimbusTest {

    // Generate 2048-bit RSA key pair in JWK format, attach some metadata
    private val jwk = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date()) // issued-at timestamp (optional)
        .generate()

    private val signRequestObject = SignRequestObjectNimbus(jwk.toRSAKey())
    private val verifier = RSASSAVerifier(jwk.toRSAPublicKey())

    @Test
    fun `given a request object, it should be signed and decoded`() {
        val requestObject = RequestObject(
            clientId = "client",
            clientIdScheme = "pre-registered",
            responseType = listOf("vp_token", "id_token"),
            presentationDefinitionUri = URL("https://foobar"),
            scope = listOf("openid"),
            idTokenType = listOf("subject_signed_id_token"),
            nonce = UUID.randomUUID().toString(),
            responseMode = "direct_post.jwt",
            responseUri = URL("https://foo"),
            state = null,
            aud = emptyList()
        )

        val jwt = signRequestObject(requestObject).getOrThrow().also { println(it) }
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

    private fun assertEqualsRequestObjectJWTClaimSet(r: RequestObject, c : JWTClaimsSet) {

        assertEquals(r.clientId, c.getStringClaim("client_id"))
        assertEquals(r.clientIdScheme, c.getStringClaim("client_id_scheme"))
        assertEquals(r.responseType.joinToString(separator = " "), c.getStringClaim("response_type"))
        assertEquals(r.presentationDefinitionUri?.urlEncoded(), c.getStringClaim("presentation_definition_uri"))
        assertEquals(r.scope.joinToString(separator = " "), c.getStringClaim("scope"))
        assertEquals(r.idTokenType.joinToString(separator = " "), c.getStringClaim("id_token_type"))
        assertEquals(r.nonce, c.getStringClaim("nonce"))
        assertEquals(r.responseMode, c.getStringClaim("response_mode"))
        assertEquals(r.responseUri?.urlEncoded(), c.getStringClaim("response_uri"))
        assertEquals(r.state, c.getStringClaim("state"))

    }

    private fun URL.urlEncoded() = URLEncoder.encode(toExternalForm(), "UTF-8")
}