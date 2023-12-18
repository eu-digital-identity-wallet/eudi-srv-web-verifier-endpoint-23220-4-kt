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
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.*
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.ResponseMode
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption.ByReference
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption.ByValue
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.SignRequestObject
import java.time.Clock
import java.util.*

/**
 * An implementation of [SignRequestObject] that uses Nimbus SDK
 */
class SignRequestObjectNimbus(private val config: SigningConfig) : SignRequestObject {

    init {
        require(config.key is AsymmetricJWK) { "Symmetric keys are not supported" }
        require(config.key.isPrivate) { "A private key is required" }
        val supportedAlgorithms = when (config.key) {
            is RSAKey -> RSASSASigner.SUPPORTED_ALGORITHMS
            is ECKey -> ECDSASigner.SUPPORTED_ALGORITHMS
            is OctetKeyPair -> Ed25519Signer.SUPPORTED_ALGORITHMS
            else -> emptyList<JWSAlgorithm>()
        }
        require(
            config.algorithm in supportedAlgorithms,
        ) { "Signing algorithm '${config.algorithm.name}' not compatible with key of type '${config.key.keyType.value}'" }
    }

    override fun invoke(
        verifierConfig: VerifierConfig,
        clock: Clock,
        presentation: Presentation.Requested,
    ): Result<Jwt> {
        val requestObject = requestObjectFromDomain(verifierConfig, clock, presentation)
        val ephemeralEcPublicKey = presentation.ephemeralEcPrivateKey
        return sign(verifierConfig.clientMetaData, ephemeralEcPublicKey, requestObject)
    }

    internal fun sign(
        clientMetaData: ClientMetaData,
        ecPublicKey: EphemeralEncryptionKeyPairJWK?,
        requestObject: RequestObject,
    ): Result<Jwt> = runCatching {
        val header = JWSHeader.Builder(config.algorithm)
            .keyID(config.key.keyID)
            .type(JOSEObjectType(AuthReqJwt))
            .build()
        val responseMode = requestObject.responseMode
        val claimSet = asClaimSet(toNimbus(clientMetaData, responseMode, ecPublicKey), requestObject)

        SignedJWT(header, claimSet)
            .apply {
                val signer = when (config.key) {
                    is RSAKey -> RSASSASigner(config.key.toRSAKey())
                    is ECKey -> ECDSASigner(config.key.toECKey())
                    is OctetKeyPair -> Ed25519Signer(config.key.toOctetKeyPair())
                    else -> error("Unsupported key of type '${config.key.keyType.value}'")
                }
                sign(signer)
            }
            .serialize()
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
            build()
        }
    }

    private fun toNimbus(
        c: ClientMetaData,
        responseMode: String,
        ecPublicKey: EphemeralEncryptionKeyPairJWK?,
    ): OIDCClientMetadata {
        val (vJwkSet, vJwkSetURI) = when (val option = c.jwkOption) {
            is ByValue -> {
                val keySet = buildList {
                    add(config.key)
                    ecPublicKey?.jwk()?.let { add(it) }
                }
                val jwkSet = JWKSet(keySet).toPublicJWKSet()
                jwkSet to null
            }

            is ByReference -> null to option.buildUrl.invoke(Unit)
        }

        return OIDCClientMetadata().apply {
            idTokenJWSAlg = JWSAlgorithm.parse(c.idTokenSignedResponseAlg)
            idTokenJWEAlg = JWEAlgorithm.parse(c.idTokenEncryptedResponseAlg)
            idTokenJWEEnc = EncryptionMethod.parse(c.idTokenEncryptedResponseEnc)
            jwkSet = vJwkSet
            jwkSetURI = vJwkSetURI?.toURI()
            setCustomField("subject_syntax_types_supported", c.subjectSyntaxTypesSupported)

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
