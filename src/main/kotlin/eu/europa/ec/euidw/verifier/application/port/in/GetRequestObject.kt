package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import eu.europa.ec.euidw.verifier.domain.*
import java.time.Clock
import java.time.Instant


interface GetRequestObject {
    suspend operator fun invoke(requestId: RequestId): QueryResponse<Jwt>

    companion object {
        fun live(
            loadPresentationByRequestId: LoadPresentationByRequestId,
            storePresentation: StorePresentation,
            signRequestObject: SignRequestObject,
            verifierConfig: VerifierConfig,
            clock: Clock
        ): GetRequestObject = GetRequestObjectLive(
            loadPresentationByRequestId,
            storePresentation,
            signRequestObject,
            verifierConfig,
            clock
        )
    }
}

private class GetRequestObjectLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock
) : GetRequestObject {

    override suspend operator fun invoke(requestId: RequestId): QueryResponse<Jwt> =
        when (val presentation = loadPresentationByRequestId(requestId)) {
            null -> QueryResponse.NotFound
            is Presentation.Requested -> requestObjectOf(presentation, clock.instant()).let { QueryResponse.Found(it) }
            else -> QueryResponse.InvalidState
        }

    private suspend fun requestObjectOf(presentation: Presentation.Requested, at: Instant): Jwt {
        val jwt = signRequestObject(verifierConfig, presentation).getOrThrow()
        val updatedPresentation = presentation.retrieveRequestObject(at).getOrThrow()
        storePresentation(updatedPresentation)
        return jwt
    }
}



