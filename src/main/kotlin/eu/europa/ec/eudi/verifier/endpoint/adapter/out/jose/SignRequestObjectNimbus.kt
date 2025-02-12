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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.ResponseMode
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.toJackson
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption.ByReference
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption.ByValue
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.SignRequestObject
import java.time.Clock
import java.util.*

/**
 * An implementation of [SignRequestObject] that uses Nimbus SDK
 */
class SignRequestObjectNimbus : SignRequestObject {

    override fun invoke(
        verifierConfig: VerifierConfig,
        clock: Clock,
        presentation: Presentation.Requested,
    ): Result<Jwt> {
        val requestObject = requestObjectFromDomain(verifierConfig, clock, presentation)
        val ephemeralEcPublicKey = presentation.ephemeralEcPrivateKey
        return sign(presentation.requestId, verifierConfig.clientMetaData, ephemeralEcPublicKey, requestObject)
    }

    internal fun sign(
        requestId: RequestId,
        clientMetaData: ClientMetaData,
        ecPublicKey: EphemeralEncryptionKeyPairJWK?,
        requestObject: RequestObject,
    ): Result<Jwt> = runCatching {
        val (key, algorithm) = requestObject.verifierId.jarSigning
        val header = JWSHeader.Builder(algorithm)
            .apply {
                when (requestObject.verifierId) {
                    is VerifierId.PreRegistered -> keyID(key.keyID)
                    is VerifierId.X509SanDns, is VerifierId.X509SanUri -> x509CertChain(key.x509CertChain)
                }
            }
            .type(JOSEObjectType(AuthReqJwt))
            .build()
        val responseMode = requestObject.responseMode
        val claimSet = asClaimSet(toNimbus(requestId, clientMetaData, responseMode, ecPublicKey), requestObject)

        SignedJWT(header, claimSet)
            .apply { sign(DefaultJWSSignerFactory().createJWSSigner(key, algorithm)) }
            .serialize()
    }

    /**
     * Maps a [RequestObject] into a Nimbus [JWTClaimsSet]
     */
    private fun asClaimSet(clientMetaData: OIDCClientMetadata?, r: RequestObject): JWTClaimsSet {
        val responseType = ResponseType(*r.responseType.map { ResponseType.Value(it) }.toTypedArray())
        val clientId = ClientID(r.verifierId.clientId)
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
            optionalClaim(
                "id_token_type",
                if (r.idTokenType.isEmpty()) {
                    null
                } else r.idTokenType.joinToString(" "),
            )
            optionalClaim(
                "presentation_definition",
                r.presentationDefinition?.let { PresentationDefinitionJackson.toJsonObject(it) },
            )
            optionalClaim("client_metadata", clientMetaData?.toJSONObject())
            optionalClaim("response_uri", r.responseUri?.toExternalForm())
            optionalClaim("presentation_definition_uri", r.presentationDefinitionUri?.toExternalForm())
            optionalClaim("dcql_query", r.dcqlQuery?.toJackson())
            optionalClaim("client_id_scheme", "x509_san_dns")
            build()
        }
    }

    private fun toNimbus(
        requestId: RequestId,
        c: ClientMetaData,
        responseMode: String,
        ecPublicKey: EphemeralEncryptionKeyPairJWK?,
    ): OIDCClientMetadata {
        val (jwkSet, jwkSetUri) = if (ecPublicKey != null) {
            when (val option = c.jwkOption) {
                is ByValue -> JWKSet(listOf(ecPublicKey.jwk())).toPublicJWKSet() to null
                is ByReference -> null to option.buildUrl(requestId)
            }
        } else null to null

        return OIDCClientMetadata().apply {
            idTokenJWSAlg = JWSAlgorithm.parse(c.idTokenSignedResponseAlg)
            idTokenJWEAlg = JWEAlgorithm.parse(c.idTokenEncryptedResponseAlg)
            idTokenJWEEnc = EncryptionMethod.parse(c.idTokenEncryptedResponseEnc)
            jwkSet?.let { this.jwkSet = it }
            jwkSetUri?.let { this.jwkSetURI = it.toURI() }
            setCustomField("subject_syntax_types_supported", c.subjectSyntaxTypesSupported)
            setCustomField("client_id_scheme", "x509_san_dns")

            if ("direct_post.jwt" == responseMode) {
                c.jarmOption.jwsAlg?.let { setCustomField("authorization_signed_response_alg", it) }
                c.jarmOption.jweAlg?.let { setCustomField("authorization_encrypted_response_alg", it) }
                c.jarmOption.encryptionMethod?.let { setCustomField("authorization_encrypted_response_enc", it) }
            }
        }
    }

    companion object {
        const val AuthReqJwt = "oauth-authz-req+jwt"
    }
}
