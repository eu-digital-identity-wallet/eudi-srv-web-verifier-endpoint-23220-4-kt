package eu.europa.ec.euidw.verifier.application.port.out.persistence

import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationId
import eu.europa.ec.euidw.verifier.domain.RequestId

/**
 * Loads a [Presentation] from a storage
 */
fun interface LoadPresentationByRequestId {
    suspend operator fun invoke(requestId: RequestId): Presentation?
}