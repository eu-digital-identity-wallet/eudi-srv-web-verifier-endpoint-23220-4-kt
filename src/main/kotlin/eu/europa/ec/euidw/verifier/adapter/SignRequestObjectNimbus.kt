package eu.europa.ec.euidw.verifier.adapter


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
import eu.europa.ec.euidw.verifier.domain.Jwt
import eu.europa.ec.euidw.verifier.application.port.`in`.RequestObject
import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject


class SignRequestObjectNimbus(private val rsaJWK: RSAKey) : SignRequestObject {


    override fun invoke(requestObject: RequestObject): Result<Jwt> = runCatching {
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.keyID).build()
        val claimSet = asClaimSet(requestObject)
        val jar = SignedJWT(header, claimSet)
        jar.sign(RSASSASigner(rsaJWK))
        val jwt = jar.serialize()
        jwt
    }


    private fun asClaimSet(r: RequestObject): JWTClaimsSet {
        val builder = AuthorizationRequest.Builder(
            ResponseType(*r.requestType.map { ResponseType.Value(it) }.toTypedArray()),
            ClientID(r.clientId)
        )

        return with(builder){
            state(State(r.state))
            scope(Scope(*r.scope.map { Scope.Value(it) }.toTypedArray()))
            responseMode(ResponseMode(r.responseMode))
            customParameter("client_id_scheme", r.clientIdScheme)
            customParameter("response_uri", r.responseUri?.toExternalForm())
            customParameter("presentation_definition_uri", r.presentationDefinitionUri?.toExternalForm())
            customParameter("aud", r.aud)
            customParameter("id_token_type", *r.idTokenType.toTypedArray())
            build()
        }.toJWTClaimsSet()

    }
  

    
}