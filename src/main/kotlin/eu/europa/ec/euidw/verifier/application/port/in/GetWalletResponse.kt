package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.prex.PresentationSubmission
import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationById
import eu.europa.ec.euidw.verifier.domain.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * Represent the [WalletResponse] as returned by the wallet
 */
@Serializable
@SerialName("wallet_response")
data class WalletResponseTO(
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("vp_token") val vpToken: JsonObject? = null,
    @SerialName("presentation_submission") val presentationSubmission: PresentationSubmission? = null,
    @SerialName("error") val error: String? = null,
    @SerialName("error_description") val errorDescription: String? = null,
)

private fun WalletResponse.toTO(): WalletResponseTO {
    return when (this) {
        is WalletResponse.IdToken -> WalletResponseTO(idToken = idToken)
        is WalletResponse.VpToken -> WalletResponseTO(
            vpToken = vpToken,
            presentationSubmission = presentationSubmission)
        is WalletResponse.IdAndVpToken -> WalletResponseTO(
            idToken = idToken,
            vpToken = vpToken,
            presentationSubmission = presentationSubmission)
        is WalletResponse.Error -> WalletResponseTO(
            error = value,
            errorDescription = description)
    }
}
/**
 * Given a [PresentationId] and a [Nonce] returns the [WalletResponse]
 */
interface GetWalletResponse {
    suspend operator fun invoke(presentationId: PresentationId, nonce: Nonce): QueryResponse<WalletResponseTO>
}

class GetWalletResponseLive(
    private val loadPresentationById: LoadPresentationById
) : GetWalletResponse {
    override suspend fun invoke(presentationId: PresentationId, nonce: Nonce): QueryResponse<WalletResponseTO>  {
        return when (val presentation = loadPresentationById(presentationId)) {
            null -> NotFound
            is Presentation.Submitted ->
                if (nonce == presentation.nonce) Found(presentation.walletResponse.toTO())
                else InvalidState
            else -> InvalidState
        }
    }

}