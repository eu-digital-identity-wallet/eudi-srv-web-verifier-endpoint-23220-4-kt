package eu.europa.ec.euidw.verifier.adapter.out.jose


import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.ResponseMode
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.domain.Jwt
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.VerifierConfig
import java.net.URL
import java.net.URLEncoder
import java.time.Clock
import java.util.*

/**
 * An implementation of [SignRequestObject] that uses Nimbus SDK
 */
class SignRequestObjectNimbus(private val rsaJWK: RSAKey) : SignRequestObject {

    override fun invoke(
        verifierConfig: VerifierConfig,
        clock: Clock,
        presentation: Presentation.Requested
    ): Result<Jwt> {
        val requestObject = requestObjectFromDomain(verifierConfig, clock, presentation)
        return sign(requestObject)
    }

    internal fun sign(requestObject: RequestObject): Result<Jwt> = runCatching {
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.keyID).build()
        val claimSet = asClaimSet(requestObject)
        with(SignedJWT(header, claimSet)) {
            sign(RSASSASigner(rsaJWK))
            serialize()
        }
    }


    /**
     * Maps a [RequestObject] into a Nimbus [JWTClaimsSet]
     */
    private fun asClaimSet(r: RequestObject): JWTClaimsSet {

        val responseType = ResponseType(*r.responseType.map { ResponseType.Value(it) }.toTypedArray())
        val clientId = ClientID(r.clientId)
        val scope = Scope(*r.scope.map { Scope.Value(it) }.toTypedArray())
        val state = State(r.state)

        val authorizationRequestClaims = with(AuthorizationRequest.Builder(responseType, clientId)) {
            state(state)
            scope(scope)
            responseMode(ResponseMode(r.responseMode))
            build()

        }.toJWTClaimsSet()

        return with(JWTClaimsSet.Builder(authorizationRequestClaims)) {

            fun optionalClaim(c: String, v: Any?) {
                v?.let { claim(c,it) }
            }
            issueTime(Date.from(r.issuedAt))
            audience(r.aud)
            claim("nonce", r.nonce)
            claim("client_id_scheme", r.clientIdScheme)
            claim("id_token_type", r.idTokenType.joinToString(" "))
            optionalClaim("presentation_definition", r.presentationDefinition?.let { PresentationDefinitionJackson.toJsonObject(it) })
            optionalClaim("response_uri", r.responseUri?.toExternalForm())
            optionalClaim("presentation_definition_uri", r.presentationDefinitionUri?.toExternalForm())
            build()
        }


    }


}