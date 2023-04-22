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
import eu.europa.ec.euidw.verifier.domain.VerifierConfig
import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.domain.Jwt
import eu.europa.ec.euidw.verifier.domain.Presentation
import java.net.URL
import java.net.URLEncoder

/**
 * An implementation of [SignRequestObject] that uses Nimbus SDK
 */
class SignRequestObjectNimbus(private val rsaJWK: RSAKey) : SignRequestObject {

    override fun invoke(verifierConfig: VerifierConfig, presentation: Presentation.Requested): Result<Jwt> {
        val requestObject = requestObjectFromDomain(verifierConfig, presentation)
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
        val maybeState = r.state?.let { State(it) }

        return with(AuthorizationRequest.Builder(responseType, clientId)) {

            fun String.urlEncoded() = URLEncoder.encode(this, "UTF-8")


            fun customParameter(s: String, ts: Collection<String>) =
                customParameter(s, *ts.toTypedArray())

            fun customOptionalURI(s: String, url: URL?): AuthorizationRequest.Builder? {
                return url?.let {
                    val encoded = it.toExternalForm().urlEncoded()
                    customParameter(s, encoded)
                }
            }

            maybeState?.let { state(it) }
            customParameter("nonce", r.nonce)
            scope(scope)
            r.presentationDefinition?.let { customParameter("presentation_definition", it.urlEncoded()) }
            responseMode(ResponseMode(r.responseMode))
            customParameter("client_id_scheme", r.clientIdScheme)
            customOptionalURI("response_uri", r.responseUri)
            customOptionalURI("presentation_definition_uri", r.presentationDefinitionUri)
            customParameter("aud", r.aud)
            customParameter("id_token_type", r.idTokenType)
            build()

        }.toJWTClaimsSet()

    }


}