package eu.europa.ec.euidw.verifier.port.`in`

import eu.europa.ec.euidw.verifier.*
import eu.europa.ec.euidw.verifier.port.out.LoadPresentationById
import eu.europa.ec.euidw.verifier.port.out.SignRequestObject
import java.net.URL

data class RequestObject(
    val clientId: String,
    val clientIdScheme: String,
    val requestType: List<String>,
    val presentationDefinitionUri: URL?,
    val scope: List<String>,
    val idTokenType: List<String>,
    val nonce: String,
    val responseMode: String,
    val responseUri: URL?,
    val aud: String?,
    val state: String?
)


class GetRequestObject(
    private val loadPresentationById: LoadPresentationById,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig
) {

    suspend operator fun invoke(presentationId: PresentationId): QueryResponse<Jwt> =
        when (val presentation = loadPresentationById(presentationId)) {
            null -> QueryResponse.NotFound
            is Presentation.Requested ->
                signedRequestObjectOf(presentation).map { QueryResponse.Found(it) }.getOrThrow()

            else -> QueryResponse.InvalidState
        }


    private fun signedRequestObjectOf(presentation: Presentation.Requested): Result<Jwt> {
        val requestObject = requestObjectOf(presentation)
        return signRequestObject(requestObject)
    }

    private fun requestObjectOf(presentation: Presentation.Requested): RequestObject {

        val type = presentation.type

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
            presentationDefinitionUri = when (type) {
                is PresentationType.IdTokenRequest -> null
                else -> verifierConfig.presentationDefinitionUriBuilder.build(presentation.id)
            },
            requestType = when (type) {
                is PresentationType.IdTokenRequest -> listOf("id_token")
                is PresentationType.VpTokenRequest -> listOf("vp_token")
                is PresentationType.IdAndVpToken -> listOf("vp_token", "id_token")
            },
            aud = when (type) {
                is PresentationType.IdTokenRequest -> null
                else -> "https://self-issued.me/v2"
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
}



