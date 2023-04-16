package eu.europa.ec.euidw.verifier.port.`in`

import eu.europa.ec.euidw.verifier.Presentation
import eu.europa.ec.euidw.verifier.PresentationDefinition
import eu.europa.ec.euidw.verifier.PresentationId
import eu.europa.ec.euidw.verifier.port.out.LoadPresentationById

fun interface GetPresentationDefinition {
    suspend fun invoke(presentationProcessId: PresentationId): QueryResponse<PresentationDefinition>
    
    companion object {

        fun live(loadPresentationById: LoadPresentationById): GetPresentationDefinition =
            GetPresentationDefinition { presentationProcessId ->
                when (val presentationProcess = loadPresentationById(presentationProcessId)) {
                    null -> QueryResponse.NotFound
                    is Presentation.Requested -> QueryResponse.Found(TODO("Implement this"))
                    else -> QueryResponse.InvalidState
                }
            }
    }
}
