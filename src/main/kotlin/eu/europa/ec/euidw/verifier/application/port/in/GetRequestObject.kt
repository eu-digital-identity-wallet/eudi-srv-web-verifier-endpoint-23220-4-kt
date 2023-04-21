package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.application.port.out.jose.requestObjectFromDomain
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationById
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import eu.europa.ec.euidw.verifier.domain.Jwt
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationId
import eu.europa.ec.euidw.verifier.domain.requestObjectRetrieved
import java.time.Clock
import java.time.Instant


interface GetRequestObject {
    suspend operator fun invoke(presentationId: PresentationId): QueryResponse<Jwt>

    companion object {
        fun live(
            loadPresentationById: LoadPresentationById,
            storePresentation: StorePresentation,
            signRequestObject: SignRequestObject,
            verifierConfig: VerifierConfig,
            clock: Clock
        ): GetRequestObject =
            GetRequestObjectLive(loadPresentationById, storePresentation, signRequestObject, verifierConfig, clock)
    }
}

internal class GetRequestObjectLive(
    private val loadPresentationById: LoadPresentationById,
    private val storePresentation: StorePresentation,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock
) : GetRequestObject {

    override suspend operator fun invoke(presentationId: PresentationId): QueryResponse<Jwt> =
        when (val presentation = loadPresentationById(presentationId)) {
            null -> QueryResponse.NotFound
            is Presentation.Requested -> requestObjectOf(presentation, clock.instant()).let { QueryResponse.Found(it) }
            else -> QueryResponse.InvalidState
        }

    private suspend fun requestObjectOf(presentation: Presentation.Requested, at: Instant): Jwt {
        val requestObject = requestObjectFromDomain(verifierConfig, presentation)
        val jwt = signRequestObject(requestObject).getOrThrow()
        val updatedPresentation = presentation.requestObjectRetrieved(at).getOrThrow()
        storePresentation(updatedPresentation)
        return jwt
    }
}



