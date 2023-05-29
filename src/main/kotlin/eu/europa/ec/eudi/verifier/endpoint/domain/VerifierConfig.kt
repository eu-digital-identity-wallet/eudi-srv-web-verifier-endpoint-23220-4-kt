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
    object ByValue : EmbedOption<Any>
    data class ByReference<ID>(val buildUrl: PresentationRelatedUrlBuilder<ID>) : EmbedOption<ID>

    companion object {
        fun <ID> byReference(urlBuilder: PresentationRelatedUrlBuilder<ID>): ByReference<ID> = ByReference(urlBuilder)
    }
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
    val subjectSyntaxTypesSupported: List<String>
)
/**
 * Verifier configuration options
 */
data class VerifierConfig(
    val clientId: String = "verifier-app",
    val clientIdScheme: String = "pre-registered",
    val requestJarOption: EmbedOption<RequestId>,
    val presentationDefinitionEmbedOption: EmbedOption<RequestId>,
    val responseUriBuilder: PresentationRelatedUrlBuilder<RequestId>,
    val maxAge: Duration,
    val clientMetaData: ClientMetaData
)
