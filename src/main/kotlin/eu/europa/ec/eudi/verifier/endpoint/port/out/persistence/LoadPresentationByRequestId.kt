package eu.europa.ec.eudi.verifier.endpoint.port.out.persistence

import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId

/**
 * Loads a [Presentation] from a storage
 */
fun interface LoadPresentationByRequestId {
    suspend operator fun invoke(requestId: RequestId): Presentation?
}