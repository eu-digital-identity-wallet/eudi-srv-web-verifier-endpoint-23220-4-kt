package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.domain.PresentationId
import java.net.URL

fun interface PresentationRelatedUrlBuilder {
    fun build(presentationId: PresentationId): URL
}

sealed interface EmbedOption {
    object ByValue: EmbedOption
    data class ByReference(val urlBuilder: PresentationRelatedUrlBuilder): EmbedOption

    companion object {
        fun byReference(urlBuilder: PresentationRelatedUrlBuilder): ByReference = ByReference(urlBuilder)
    }
}



/**
 * Verifier configuration options
 */
data class VerifierConfig(
    val clientId: String = "verifier-app",
    val clientIdScheme: String ="pre-registered",
    val requestJarOption: EmbedOption,
    val presentationDefinitionEmbedOption: EmbedOption,
    val responseUriBuilder: PresentationRelatedUrlBuilder
)
