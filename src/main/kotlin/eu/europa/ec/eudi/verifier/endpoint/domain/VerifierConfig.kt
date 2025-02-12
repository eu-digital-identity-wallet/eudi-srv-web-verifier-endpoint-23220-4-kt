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
package eu.europa.ec.eudi.verifier.endpoint.domain

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWK
import java.net.URL
import java.security.cert.X509Certificate
import java.time.Duration

typealias PresentationRelatedUrlBuilder<ID> = (ID) -> URL

/**
 * This is a configuration option for properties like JAR request/request_uri or
 * presentation_definition/presentation_definition_uri
 * where can be embedded either by value or by reference
 */
sealed interface EmbedOption<in ID> {
    data object ByValue : EmbedOption<Any>
    data class ByReference<ID>(val buildUrl: PresentationRelatedUrlBuilder<ID>) : EmbedOption<ID>

    companion object {
        fun <ID> byReference(urlBuilder: PresentationRelatedUrlBuilder<ID>): ByReference<ID> = ByReference(urlBuilder)
    }
}

/**
 * Configure option for response mode
 */
enum class ResponseModeOption {
    DirectPost,
    DirectPostJwt,
}

sealed interface JarmOption {

    val jwsAlg: String?
        get() = when (this) {
            is Signed -> algorithm
            is SignedAndEncrypted -> signed.algorithm
            else -> null
        }

    val jweAlg: String?
        get() = when (this) {
            is Encrypted -> algorithm
            is SignedAndEncrypted -> encrypted.algorithm
            else -> null
        }

    val encryptionMethod: String?
        get() = when (this) {
            is Encrypted -> encode
            is SignedAndEncrypted -> encrypted.encode
            else -> null
        }

    data class Signed(val algorithm: String) : JarmOption
    data class Encrypted(val algorithm: String, val encode: String) : JarmOption
    data class SignedAndEncrypted(
        val signed: Signed,
        val encrypted: Encrypted,
    ) : JarmOption
}

/**
 * By OpenID Connect Dynamic Client Registration specification
 *
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html">OpenID Connect Dynamic Client Registration specification</a>
 */
data class ClientMetaData(
    val jwkOption: EmbedOption<RequestId>,
    val idTokenSignedResponseAlg: String,
    val idTokenEncryptedResponseAlg: String,
    val idTokenEncryptedResponseEnc: String,
    val subjectSyntaxTypesSupported: List<String>,
    val jarmOption: JarmOption,
)

/**
 * Configuration options for signing.
 */
data class SigningConfig(
    val key: JWK,
    val algorithm: JWSAlgorithm,
) {
    init {
        // Verify only asymmetric signature algorithms are accepted
        require(algorithm in JWSAlgorithm.Family.SIGNATURE) { "'${algorithm.name}' is not a valid signature algorithm" }

        // Verify a JWSSigner can be instantiated with the provided key/algorithm combo
        runCatching {
            DefaultJWSSignerFactory().createJWSSigner(key, algorithm)
        }.getOrElse { throw IllegalArgumentException("Invalid configuration", it) }
    }

    /**
     * The signing [X509Certificate].
     */
    val certificate: X509Certificate
        get() = key.parsedX509CertChain.first()
}

typealias OriginalClientId = String
typealias ClientId = String

/**
 * Client Id (as defined by OpenId 4 VP) of the Verifier Endpoint.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-scheme-an">https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-scheme-an</a>
 */
sealed interface VerifierId {
    val originalClientId: OriginalClientId
    val jarSigning: SigningConfig
    val clientId: ClientId

    /**
     * This value represents the RFC6749 default behavior,
     * i.e., the Client Identifier needs to be known to the Wallet in advance of the Authorization Request
     * The Verifier's metadata is obtained using (RFC7591) or through out-of-band mechanisms.
     */
    data class PreRegistered(
        override val originalClientId: String,
        override val jarSigning: SigningConfig,
    ) : VerifierId {
        override val clientId: ClientId = originalClientId
    }

    /**
     * When the Client Identifier Scheme is x509_san_dns, the Client Identifier
     * MUST be a DNS name and match a dNSName Subject Alternative Name (SAN) RFC5280
     * entry in the leaf certificate passed with the request
     */
    data class X509SanDns(
        override val originalClientId: String,
        override val jarSigning: SigningConfig,
    ) : VerifierId {
        init {
            require(jarSigning.certificate.containsSanDns(originalClientId)) {
                "Original Client Id '$originalClientId' not contained in 'DNS' Subject Alternative Names of JAR Signing Certificate."
            }
        }

        override val clientId: ClientId = originalClientId
    }

    /**
     * When the Client Identifier Scheme is x509_san_uri, the Client Identifier
     * MUST be a URI and match a uniformResourceIdentifier Subject Alternative Name (SAN) RFC5280
     * entry in the leaf certificate passed with the request
     */
    data class X509SanUri(
        override val originalClientId: String,
        override val jarSigning: SigningConfig,
    ) : VerifierId {
        init {
            require(jarSigning.certificate.containsSanUri(originalClientId)) {
                "Original Client Id '$originalClientId' not contained in 'URI' Subject Alternative Names of JAR Signing Certificate."
            }
        }

        override val clientId: ClientId = "x509_san_uri:$originalClientId"
    }
}

/**
 * Verifier configuration options
 */
data class VerifierConfig(
    val verifierId: VerifierId,
    val requestJarOption: EmbedOption<RequestId>,
    val presentationDefinitionEmbedOption: EmbedOption<RequestId>,
    val responseModeOption: ResponseModeOption,
    val responseUriBuilder: PresentationRelatedUrlBuilder<RequestId>,
    val maxAge: Duration,
    val clientMetaData: ClientMetaData,
)

/**
 * Checks if [value] is a Subject Alternative Name of [type] in this [X509Certificate].
 */
private fun X509Certificate.containsSan(value: String, type: SanType) =
    value in this.san(type)

/**
 * Checks if [value] is a 'DNS' Subject Alternative Name in this [X509Certificate].
 */
private fun X509Certificate.containsSanDns(value: String) =
    containsSan(value, SanType.DNS)

/**
 * Checks if [value] is a 'URI' Subject Alternative Name in this [X509Certificate].
 */
private fun X509Certificate.containsSanUri(value: String) =
    containsSan(value, SanType.URI)

/**
 * Gets the Subject Alternative Names of the provided [type] from this [X509Certificate].
 */
private fun X509Certificate.san(type: SanType) =
    buildList {
        subjectAlternativeNames
            ?.filter { subjectAltNames -> !subjectAltNames.isNullOrEmpty() && subjectAltNames.size == 2 }
            ?.forEach { entry ->
                val altNameType = entry[0] as Int
                entry[1]?.takeIf { altNameType == type.asInt() }?.let { add(it as String) }
            }
    }

/**
 * Types of Subject Alternative Names.
 */
private enum class SanType {
    URI,
    DNS,
}

/**
 * Gets the numeric value of this [SanType].
 *
 * See also https://www.rfc-editor.org/rfc/rfc5280.html
 *
 */
private fun SanType.asInt() =
    when (this) {
        SanType.URI -> 6
        SanType.DNS -> 2
    }
