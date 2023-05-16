package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationById
import eu.europa.ec.euidw.verifier.domain.*

/**
 * Given a [RequestId] returns the [WalletResponse]
 */
interface GetWalletResponse {
    suspend operator fun invoke(presentationId: PresentationId): QueryResponse<WalletResponse>
}

class GetWalletResponseLive(
    private val loadPresentationById: LoadPresentationById
) : GetWalletResponse {
    override suspend fun invoke(presentationId: PresentationId): QueryResponse<WalletResponse> {
        fun foundSubmittedOrInvalid(p: Presentation.Submitted) = Found(p.walletResponse)

        return when (val presentation = loadPresentationById(presentationId)) {
            null -> NotFound
            is Presentation.Submitted -> foundSubmittedOrInvalid(presentation)
            else -> InvalidState
        }
    }
}