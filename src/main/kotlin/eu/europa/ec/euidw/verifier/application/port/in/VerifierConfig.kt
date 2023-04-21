package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.domain.PresentationId
import java.net.URL

fun interface PresentationRelatedUrlBuilder {
    fun build(presentationId: PresentationId): URL
}

sealed interface EncodeOption {
    object ByValue: EncodeOption
    data class ByReference(val urlBuilder: PresentationRelatedUrlBuilder): EncodeOption

    companion object {
        fun byReference(urlBuilder: PresentationRelatedUrlBuilder): EncodeOption.ByReference =
            ByReference(urlBuilder)
    }
}

/**
 * Verifier configuration options
 */
data class VerifierConfig(
    val clientId: String = "verifier-app",
    val clientIdScheme: String ="pre-registered",
    val requestUriBuilder: PresentationRelatedUrlBuilder,
    val presentationDefinitionOption: EncodeOption,
    val responseUriBuilder: PresentationRelatedUrlBuilder
)
