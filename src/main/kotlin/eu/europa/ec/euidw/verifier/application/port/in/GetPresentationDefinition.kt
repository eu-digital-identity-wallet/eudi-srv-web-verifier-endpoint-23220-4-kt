package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.prex.PresentationExchange
import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationType
import eu.europa.ec.euidw.verifier.domain.RequestId

interface GetPresentationDefinition {
    suspend operator fun invoke(requestId: RequestId): QueryResponse<String>

    companion object {
        fun live(loadPresentationByRequestId: LoadPresentationByRequestId): GetPresentationDefinition =
            GetPresentationDefinitionLive(loadPresentationByRequestId)
    }
}


private class GetPresentationDefinitionLive(private val loadPresentationByRequestId: LoadPresentationByRequestId) :
    GetPresentationDefinition {
    override suspend fun invoke(requestId: RequestId): QueryResponse<String> {
        return when (val presentation = loadPresentationByRequestId(requestId)) {
            null -> NotFound
            is Presentation.RequestObjectRetrieved ->
                presentationDefinitionOf(presentation)
                    ?.toJson()
                    ?.let { Found(it) }
                    ?: InvalidState
            else -> InvalidState
        }
    }

    private fun presentationDefinitionOf(presentation: Presentation): PresentationDefinition? =
        when (val type = presentation.type) {
            is PresentationType.IdTokenRequest -> null
            is PresentationType.VpTokenRequest -> type.presentationDefinition
            is PresentationType.IdAndVpToken -> type.presentationDefinition
        }

    private fun PresentationDefinition.toJson() =
        with(PresentationExchange.jsonParser) { encode() }
}
