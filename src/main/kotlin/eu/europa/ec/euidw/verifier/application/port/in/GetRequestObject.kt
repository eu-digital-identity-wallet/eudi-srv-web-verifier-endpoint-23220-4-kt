package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import eu.europa.ec.euidw.verifier.domain.*
import java.time.Clock
import java.time.Instant


interface GetRequestObject {
    suspend operator fun invoke(requestId: RequestId): QueryResponse<Jwt>

}

class GetRequestObjectLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock
) : GetRequestObject {

    override suspend operator fun invoke(requestId: RequestId): QueryResponse<Jwt> =
        when (val presentation = loadPresentationByRequestId(requestId)) {
            null -> NotFound
            is Presentation.Requested -> Found(requestObjectOf(presentation, clock.instant()))
            else -> InvalidState
        }

    private suspend fun requestObjectOf(presentation: Presentation.Requested, at: Instant): Jwt {
        val jwt = signRequestObject(verifierConfig, presentation).getOrThrow()
        val updatedPresentation = presentation.retrieveRequestObject(at).getOrThrow()
        storePresentation(updatedPresentation)
        return jwt
    }
}



