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

import java.net.URL
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
    val jwkOption: EmbedOption<Any>,
    val idTokenSignedResponseAlg: String,
    val idTokenEncryptedResponseAlg: String,
    val idTokenEncryptedResponseEnc: String,
    val subjectSyntaxTypesSupported: List<String>,
    val jarmOption: JarmOption,
)

/**
 * Verifier configuration options
 */
data class VerifierConfig(
    val clientId: String = "verifier-app",
    val clientIdScheme: String = "pre-registered",
    val requestJarOption: EmbedOption<RequestId>,
    val presentationDefinitionEmbedOption: EmbedOption<RequestId>,
    val responseModeOption: ResponseModeOption,
    val responseUriBuilder: PresentationRelatedUrlBuilder<RequestId>,
    val maxAge: Duration,
    val clientMetaData: ClientMetaData,
)
