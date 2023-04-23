package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationType
import eu.europa.ec.euidw.verifier.domain.RequestId

interface GetPresentationDefinition {
    suspend operator fun invoke(requestId: RequestId): QueryResponse<PresentationDefinition>
}


class GetPresentationDefinitionLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId
) : GetPresentationDefinition {
    override suspend fun invoke(requestId: RequestId): QueryResponse<PresentationDefinition> {
        fun foundOrInvalid(p: Presentation) =
            presentationDefinitionOf(p)?.let { Found(it) } ?: InvalidState

        return when (val presentation = loadPresentationByRequestId(requestId)) {
            null -> NotFound
            is Presentation.RequestObjectRetrieved -> foundOrInvalid(presentation)
            else -> InvalidState
        }
    }

    private fun presentationDefinitionOf(presentation: Presentation): PresentationDefinition? =
        when (val type = presentation.type) {
            is PresentationType.IdTokenRequest -> null
            is PresentationType.VpTokenRequest -> type.presentationDefinition
            is PresentationType.IdAndVpToken -> type.presentationDefinition
        }

}
