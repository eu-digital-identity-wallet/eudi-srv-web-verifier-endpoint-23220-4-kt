package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.RequestId
import eu.europa.ec.euidw.verifier.domain.presentationDefinitionOrNull

/**
 * Given a [RequestId] returns the [PresentationDefinition] if
 * the [Presentation] is in state [Presentation.RequestObjectRetrieved] and if
 * it is related to verifiable credentials presentation
 */
interface GetPresentationDefinition {
    suspend operator fun invoke(requestId: RequestId): QueryResponse<PresentationDefinition>
}


class GetPresentationDefinitionLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId
) : GetPresentationDefinition {
    override suspend fun invoke(requestId: RequestId): QueryResponse<PresentationDefinition> {
        fun foundOrInvalid(p: Presentation) =
            p.type.presentationDefinitionOrNull?.let { Found(it) } ?: InvalidState

        return when (val presentation = loadPresentationByRequestId(requestId)) {
            null -> NotFound
            is Presentation.RequestObjectRetrieved -> foundOrInvalid(presentation)
            else -> InvalidState
        }
    }

}
