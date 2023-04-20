package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationById
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationId

interface GetPresentationDefinition {
    suspend fun invoke(presentationProcessId: PresentationId): QueryResponse<PresentationDefinition>

    companion object {
        fun live( loadPresentationById: LoadPresentationById): GetPresentationDefinition =
            GetPresentationDefinitionLive(loadPresentationById)
    }
}


private class GetPresentationDefinitionLive(private val loadPresentationById: LoadPresentationById) :
    GetPresentationDefinition {
    override suspend fun invoke(presentationProcessId: PresentationId): QueryResponse<PresentationDefinition> {
        return when (val presentationProcess = loadPresentationById(presentationProcessId)) {
            null -> QueryResponse.NotFound
            is Presentation.Requested -> QueryResponse.Found(TODO("Implement this"))
            else -> QueryResponse.InvalidState
        }
    }
}
