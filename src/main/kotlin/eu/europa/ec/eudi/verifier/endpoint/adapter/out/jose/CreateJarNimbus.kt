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

import arrow.core.Either
import arrow.core.flatMap
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.X25519Encrypter
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
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
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.toJackson
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata.toJsonObject
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.CreateJar
import java.time.Clock
import java.util.*

/**
 * An implementation of [CreateJar] that uses Nimbus SDK
 */
class CreateJarNimbus : CreateJar {

    override fun invoke(
        verifierConfig: VerifierConfig,
        clock: Clock,
        presentation: Presentation.Requested,
        walletNonce: String?,
        walletJarEncryptionRequirement: EncryptionRequirement,
    ): Either<Throwable, Jwt> {
        val requestObject = requestObjectFromDomain(verifierConfig, clock, presentation)
        val jarmEncryptionEphemeralKey = presentation.jarmEncryptionEphemeralKey
        val signedJar = sign(verifierConfig.clientMetaData, jarmEncryptionEphemeralKey, requestObject, walletNonce)
        return when (walletJarEncryptionRequirement) {
            EncryptionRequirement.NotRequired -> signedJar.map { it.serialize() }
            is EncryptionRequirement.Required -> signedJar.flatMap { encrypt(walletJarEncryptionRequirement, it) }.map { it.serialize() }
        }
    }

    internal fun sign(
        clientMetaData: ClientMetaData,
        jarmEncryptionEphemeralKey: EphemeralEncryptionKeyPairJWK?,
        requestObject: RequestObject,
        walletNonce: String?,
    ): Either<Throwable, SignedJWT> = Either.catch {
        val (key, algorithm) = requestObject.verifierId.jarSigning
        val header = JWSHeader.Builder(algorithm)
            .apply {
                when (requestObject.verifierId) {
                    is VerifierId.PreRegistered -> keyID(key.keyID)
                    is VerifierId.X509SanDns, is VerifierId.X509SanUri -> x509CertChain(key.x509CertChain)
                }
            }
            .type(JOSEObjectType(RFC9101.REQUEST_OBJECT_MEDIA_SUBTYPE))
            .build()
        val responseMode = requestObject.responseMode
        val claimSet = asClaimSet(toNimbus(clientMetaData, responseMode, jarmEncryptionEphemeralKey), requestObject, walletNonce)

        SignedJWT(header, claimSet).apply { sign(DefaultJWSSignerFactory().createJWSSigner(key, algorithm)) }
    }

    internal fun encrypt(
        walletJarEncryptionRequirement: EncryptionRequirement.Required,
        signed: SignedJWT,
    ): Either<Throwable, JWEObject> = Either.catch {
        val (walletJarEncryptionKey, encryptionAlgorithm, encryptionMethod) = walletJarEncryptionRequirement
        val encrypter = when (walletJarEncryptionKey) {
            is RSAKey -> RSAEncrypter(walletJarEncryptionKey)
            is ECKey -> ECDHEncrypter(walletJarEncryptionKey)
            is OctetKeyPair -> X25519Encrypter(walletJarEncryptionKey)
            else -> error("Unsupported JWK type '${walletJarEncryptionKey::javaClass.name}'")
        }

        val header = JWEHeader.Builder(encryptionAlgorithm, encryptionMethod)
            .contentType("JWT")
            .build()
        val payload = Payload(signed)

        JWEObject(header, payload).apply { encrypt(encrypter) }
    }

    /**
     * Maps a [RequestObject] into a Nimbus [JWTClaimsSet]
     */
    private fun asClaimSet(clientMetaData: OIDCClientMetadata?, r: RequestObject, walletNonce: String?): JWTClaimsSet {
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
                OpenId4VPSpec.PRESENTATION_DEFINITION,
                r.presentationDefinition?.let { PresentationDefinitionJackson.toJsonObject(it) },
            )
            optionalClaim("client_metadata", clientMetaData?.toJSONObject())
            optionalClaim(OpenId4VPSpec.RESPONSE_URI, r.responseUri?.toExternalForm())
            optionalClaim(OpenId4VPSpec.PRESENTATION_DEFINITION_URI, r.presentationDefinitionUri?.toExternalForm())
            optionalClaim(OpenId4VPSpec.DCQL_QUERY, r.dcqlQuery?.toJackson())
            optionalClaim(OpenId4VPSpec.TRANSACTION_DATA, r.transactionData?.toJackson())
            optionalClaim(OpenId4VPSpec.WALLET_NONCE, walletNonce)
            build()
        }
    }

    private fun toNimbus(
        c: ClientMetaData,
        responseMode: String,
        ecPublicKey: EphemeralEncryptionKeyPairJWK?,
    ): OIDCClientMetadata {
        val jwkSet = if (ecPublicKey != null) {
            JWKSet(listOf(ecPublicKey.jwk())).toPublicJWKSet()
        } else null

        return OIDCClientMetadata().apply {
            idTokenJWSAlg = JWSAlgorithm.parse(c.idTokenSignedResponseAlg)
            idTokenJWEAlg = JWEAlgorithm.parse(c.idTokenEncryptedResponseAlg)
            idTokenJWEEnc = EncryptionMethod.parse(c.idTokenEncryptedResponseEnc)
            jwkSet?.let { this.jwkSet = it }
            setCustomField("subject_syntax_types_supported", c.subjectSyntaxTypesSupported)

            if (OpenId4VPSpec.DIRECT_POST_JWT == responseMode) {
                c.jarmOption.jwsAlg?.let { setCustomField("authorization_signed_response_alg", it) }
                c.jarmOption.jweAlg?.let { setCustomField("authorization_encrypted_response_alg", it) }
                c.jarmOption.encryptionMethod?.let { setCustomField("authorization_encrypted_response_enc", it) }
            }

            setCustomField(OpenId4VPSpec.VP_FORMATS, c.vpFormats.toJsonObject().toJackson())
        }
    }
}
