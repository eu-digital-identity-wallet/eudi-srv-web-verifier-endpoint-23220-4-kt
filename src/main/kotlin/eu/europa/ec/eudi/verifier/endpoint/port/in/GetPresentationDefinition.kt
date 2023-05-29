package eu.europa.ec.eudi.verifier.endpoint.port.`in`

import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.verifier.endpoint.port.`in`.QueryResponse.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.presentationDefinitionOrNull

/**
 * Given a [RequestId] returns the [PresentationDefinition] if
 * the [Presentation] is in state [Presentation.RequestObjectRetrieved] and if
 * it is related to verifiable credentials presentation
 */
fun interface GetPresentationDefinition {
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
