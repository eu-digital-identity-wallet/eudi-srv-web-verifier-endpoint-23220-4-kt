package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.prex.PresentationSubmission
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import eu.europa.ec.euidw.verifier.domain.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.time.Clock


/**
 * Represent the [AuthorisationResponse]
 */
@Serializable
@SerialName("authorisation_response")
data class AuthorisationResponseTO(
    @SerialName("state") val state: String,// this is the request_id
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("vp_token") val vpToken: JsonObject? = null,
    @SerialName("presentation_submission") val presentationSubmission: PresentationSubmission? = null,
)

/**
 * Carrier of [ValidationError]
 */
data class WalletResponseValidationException(val error: WalletResponseValidationError) : RuntimeException()

enum class WalletResponseValidationError {
    MissingIdToken,
    MissingVpTokenOrPresentationSubmission,
    MissingIdTokenOrVpTokenOrPresentationSubmission,
}

internal fun AuthorisationResponseTO.toDomain(presentation: Presentation.RequestObjectRetrieved): Result<WalletResponse> {
    fun requiredIdToken() =
        if (idToken != null) Result.success(WalletResponse.IdToken(idToken))
        else Result.failure(WalletResponseValidationException(WalletResponseValidationError.MissingIdToken))

    fun requiredVpToken() =
        if (vpToken != null && presentationSubmission != null)
            Result.success(WalletResponse.VpToken(vpToken, presentationSubmission))
        else Result.failure(WalletResponseValidationException(WalletResponseValidationError.MissingVpTokenOrPresentationSubmission))

    fun requiredIdandVpToken() =
        if (idToken != null && vpToken != null && presentationSubmission != null)
            Result.success(
                WalletResponse.IdAndVpToken(
                    idToken = idToken,
                    vpToken = vpToken,
                    presentationSubmission = presentationSubmission
                )
            )
        else Result.failure(WalletResponseValidationException(WalletResponseValidationError.MissingIdTokenOrVpTokenOrPresentationSubmission))

    return runCatching {
        when (presentation.type) {
            is PresentationType.IdTokenRequest -> WalletResponse.IdToken(requiredIdToken().getOrThrow().idToken)
            is PresentationType.VpTokenRequest -> WalletResponse.VpToken(
                requiredVpToken().getOrThrow().vpToken,
                requiredVpToken().getOrThrow().presentationSubmission
            )

            is PresentationType.IdAndVpToken -> WalletResponse.IdAndVpToken(
                requiredIdandVpToken().getOrThrow().idToken,
                requiredIdandVpToken().getOrThrow().vpToken,
                requiredIdandVpToken().getOrThrow().presentationSubmission
            )
        }
    }
}

/**
 * This is use case 12 of the [Presentation] process.
 *
 * The caller (wallet) may POST the [AuthorisationResponseTO] to the verifier back-end
 */
fun interface PostWalletResponse {
    suspend operator fun invoke(authorisationResponseObject: AuthorisationResponseTO): QueryResponse<Jwt>
}

class PostWalletResponseLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val clock: Clock
) : PostWalletResponse {

    override suspend operator fun invoke(authorisationResponseObject: AuthorisationResponseTO): QueryResponse<String> {

        val requestId = RequestId(authorisationResponseObject.state)

        return when (val presentation = loadPresentationByRequestId(requestId)) {
            null -> QueryResponse.NotFound
            is Presentation.RequestObjectRetrieved ->
                submit(presentation, authorisationResponseObject).fold(
                    onSuccess = { QueryResponse.Found("OK") },
                    onFailure = { QueryResponse.InvalidState }
                )

            else -> QueryResponse.InvalidState
        }
    }

    private suspend fun submit(
        presentation: Presentation.RequestObjectRetrieved,
        authorisationResponseObject: AuthorisationResponseTO
    ): Result<Presentation.Submitted> =

        runCatching {
            // add the wallet response to the presentation
            val walletResponse = authorisationResponseObject.toDomain(presentation).getOrThrow()
            val authorisationResponse = presentation.submit(clock, walletResponse).getOrThrow()
            // store the presentation
            storePresentation(authorisationResponse)
            authorisationResponse
        }

}



