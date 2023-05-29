package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose


import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.ResponseMode
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.eudi.verifier.endpoint.domain.ClientMetaData
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption.ByReference
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption.ByValue
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.SignRequestObject
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
        return sign(verifierConfig.clientMetaData, requestObject)
    }

    internal fun sign(
        clientMetaData: ClientMetaData,
        requestObject: RequestObject
    ): Result<Jwt> = runCatching {
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.keyID).build()
        val claimSet = asClaimSet(toNimbus(clientMetaData), requestObject)
        with(SignedJWT(header, claimSet)) {
            sign(RSASSASigner(rsaJWK))
            serialize()
        }
    }

    /**
     * Maps a [RequestObject] into a Nimbus [JWTClaimsSet]
     */
    private fun asClaimSet(clientMetaData: OIDCClientMetadata?, r: RequestObject): JWTClaimsSet {

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
                v?.let { claim(c, it) }
            }
            issueTime(Date.from(r.issuedAt))
            audience(r.aud)
            claim("nonce", r.nonce)
            claim("client_id_scheme", r.clientIdScheme)
            optionalClaim(
                "id_token_type",
                if (r.idTokenType.isEmpty()) null
                else r.idTokenType.joinToString(" ")
            )
            optionalClaim(
                "presentation_definition",
                r.presentationDefinition?.let { PresentationDefinitionJackson.toJsonObject(it) })
            optionalClaim("client_metadata", clientMetaData?.toJSONObject())
            optionalClaim("response_uri", r.responseUri?.toExternalForm())
            optionalClaim("presentation_definition_uri", r.presentationDefinitionUri?.toExternalForm())
            build()
        }


    }

    private fun toNimbus(c: ClientMetaData): OIDCClientMetadata {

        val (vJwkSet, vJwkSetURI) = when (val option = c.jwkOption) {
            is ByValue -> JWKSet(rsaJWK).toPublicJWKSet() to null
            is ByReference -> null to option.buildUrl.invoke(Unit)
        }
        return OIDCClientMetadata().apply {
            idTokenJWSAlg = JWSAlgorithm.parse(c.idTokenSignedResponseAlg)
            idTokenJWEAlg = JWEAlgorithm.parse(c.idTokenEncryptedResponseAlg)
            idTokenJWEEnc = EncryptionMethod.parse(c.idTokenEncryptedResponseEnc)
            jwkSet = vJwkSet
            jwkSetURI = vJwkSetURI?.toURI()
            setCustomField("subject_syntax_types_supported", c.subjectSyntaxTypesSupported)
        }
    }


}