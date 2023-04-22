package eu.europa.ec.euidw.verifier.adapter.out.jose

import eu.europa.ec.euidw.prex.PresentationExchange
import eu.europa.ec.euidw.verifier.domain.EmbedOption
import eu.europa.ec.euidw.verifier.domain.VerifierConfig
import eu.europa.ec.euidw.verifier.domain.IdTokenType
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationType
import java.net.URL

internal data class RequestObject(
    val clientId: String,
    val clientIdScheme: String,
    val responseType: List<String>,
    val presentationDefinitionUri: URL?,
    val presentationDefinition: String? = null,
    val scope: List<String>,
    val idTokenType: List<String>,
    val nonce: String,
    val responseMode: String,
    val responseUri: URL?,
    val aud: List<String>,
    val state: String
)

internal fun requestObjectFromDomain(verifierConfig: VerifierConfig, presentation: Presentation.Requested): RequestObject {
    val type = presentation.type
    val scope = when (type) {
        is PresentationType.IdTokenRequest -> listOf("openid")
        is PresentationType.VpTokenRequest -> emptyList()
        is PresentationType.IdAndVpToken -> listOf("openid")
    }
    val idTokenType = when (type) {
        is PresentationType.IdTokenRequest -> type.idTokenType
        is PresentationType.VpTokenRequest -> emptyList()
        is PresentationType.IdAndVpToken -> type.idTokenType
    }.map {
        when (it) {
            IdTokenType.AttesterSigned -> "attester_signed_id_token"
            IdTokenType.SubjectSigned -> "subject_signed_id_token"
        }
    }
    val maybePresentationDefinition = when (type) {
        is PresentationType.IdTokenRequest -> null
        is PresentationType.VpTokenRequest -> type.presentationDefinition
        is PresentationType.IdAndVpToken -> type.presentationDefinition
    }
    val presentationDefinitionUri = maybePresentationDefinition?.let {
        when (val option = verifierConfig.presentationDefinitionEmbedOption) {
            is EmbedOption.ByValue -> null
            is EmbedOption.ByReference -> option.buildUrl(presentation.requestId)
        }
    }
    val presentationDefinition = maybePresentationDefinition?.let { presentationDefinition ->
        when (verifierConfig.presentationDefinitionEmbedOption) {
            is EmbedOption.ByValue -> with(PresentationExchange.jsonParser) { presentationDefinition.encode() }
            is EmbedOption.ByReference -> null
        }
    }
    val responseType = when (type) {
        is PresentationType.IdTokenRequest -> listOf("id_token")
        is PresentationType.VpTokenRequest -> listOf("vp_token")
        is PresentationType.IdAndVpToken -> listOf("vp_token", "id_token")
    }

    val aud = when (type) {
        is PresentationType.IdTokenRequest -> emptyList()
        else -> listOf("https://self-issued.me/v2")
    }

    return RequestObject(
        clientId = verifierConfig.clientId,
        clientIdScheme = verifierConfig.clientIdScheme,
        scope = scope,
        idTokenType = idTokenType,
        presentationDefinitionUri = presentationDefinitionUri,
        presentationDefinition = presentationDefinition,
        responseType = responseType,
        aud = aud,
        nonce = presentation.id.value.toString(),
        state = presentation.requestId.value,
        responseMode = "direct_post.jwt",
        responseUri = verifierConfig.responseUriBuilder(presentation.requestId)
    )
}

