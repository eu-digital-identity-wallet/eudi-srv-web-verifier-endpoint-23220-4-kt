package eu.europa.ec.euidw.verifier.application.port.out.jose

import eu.europa.ec.euidw.prex.PresentationExchange
import eu.europa.ec.euidw.verifier.application.port.`in`.EncodeOption
import eu.europa.ec.euidw.verifier.application.port.`in`.VerifierConfig
import eu.europa.ec.euidw.verifier.domain.IdTokenType
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationType
import java.net.URL

data class RequestObject(
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
    val state: String?
)
fun requestObjectFromDomain(verifierConfig: VerifierConfig, presentation: Presentation.Requested): RequestObject {
    val type = presentation.type
    val maybePresentationDefinition = when (type) {
        is PresentationType.IdTokenRequest -> null
        is PresentationType.VpTokenRequest -> type.presentationDefinition
        is PresentationType.IdAndVpToken -> type.presentationDefinition
    }
    return RequestObject(
        clientId = verifierConfig.clientId,
        clientIdScheme = verifierConfig.clientIdScheme,
        scope = when (type) {
            is PresentationType.IdTokenRequest -> listOf("openid")
            is PresentationType.VpTokenRequest -> emptyList()
            is PresentationType.IdAndVpToken -> listOf("openid")
        },
        idTokenType = when (type) {
            is PresentationType.IdTokenRequest -> type.idTokenType
            is PresentationType.VpTokenRequest -> emptyList()
            is PresentationType.IdAndVpToken -> type.idTokenType
        }.map { it.asString() },
        presentationDefinitionUri = maybePresentationDefinition?.let {
            when (val option = verifierConfig.presentationDefinitionOption) {
                is EncodeOption.ByValue -> null
                is EncodeOption.ByReference -> option.urlBuilder.build(presentation.id)
            }
        },
        presentationDefinition = maybePresentationDefinition?.let { presentationDefinition ->
            when (verifierConfig.presentationDefinitionOption) {
                is EncodeOption.ByValue -> with(PresentationExchange.jsonParser) {
                    presentationDefinition.encode()
                }
                is EncodeOption.ByReference -> null
            }
        },
        responseType = when (type) {
            is PresentationType.IdTokenRequest -> listOf("id_token")
            is PresentationType.VpTokenRequest -> listOf("vp_token")
            is PresentationType.IdAndVpToken -> listOf("vp_token", "id_token")
        },
        aud = when (type) {
            is PresentationType.IdTokenRequest -> emptyList()
            else -> listOf("https://self-issued.me/v2")
        },
        nonce = presentation.id.value.toString(),
        state = null,
        responseMode = "direct_post.jwt",
        responseUri = verifierConfig.responseUriBuilder.build(presentation.id)
    )
}

private fun IdTokenType.asString(): String = when (this) {
    IdTokenType.AttesterSigned -> "attester_signed_id_token"
    IdTokenType.SubjectSigned -> "subject_signed_id_token"
}