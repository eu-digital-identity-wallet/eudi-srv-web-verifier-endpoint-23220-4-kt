package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.domain.PresentationId
import java.net.URL

fun interface PresentationRelatedUrlBuilder {
    fun build(presentationId: PresentationId): URL
}

data class VerifierConfig(
    val clientId: String = "verifier-app",
    val clientIdScheme: String ="pre-registered",
    val requestUriBuilder: PresentationRelatedUrlBuilder,
    val presentationDefinitionUriBuilder : PresentationRelatedUrlBuilder,
    val responseUriBuilder: PresentationRelatedUrlBuilder
)
