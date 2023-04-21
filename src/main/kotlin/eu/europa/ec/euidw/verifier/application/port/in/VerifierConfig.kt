package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.domain.PresentationId
import java.net.URL

typealias PresentationRelatedUrlBuilder = (PresentationId) -> URL

/**
 * This is a configuration option for properties like JAR request/request_uri or
 * presentation_definition/presentation_definition_uri
 * where can be embedded either by value or by reference
 */
sealed interface EmbedOption {
    object ByValue : EmbedOption
    data class ByReference(val buildUrl: PresentationRelatedUrlBuilder) : EmbedOption

    companion object {
        fun byReference(urlBuilder: PresentationRelatedUrlBuilder): ByReference = ByReference(urlBuilder)
    }
}

/**
 * Verifier configuration options
 */
data class VerifierConfig(
    val clientId: String = "verifier-app",
    val clientIdScheme: String = "pre-registered",
    val requestJarOption: EmbedOption,
    val presentationDefinitionEmbedOption: EmbedOption,
    val responseUriBuilder: PresentationRelatedUrlBuilder
)
