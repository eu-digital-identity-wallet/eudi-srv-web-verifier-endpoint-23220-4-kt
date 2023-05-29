package eu.europa.ec.eudi.verifier.endpoint.port.out.persistence

import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId

/**
 * Loads a [Presentation] from a storage
 */
fun interface LoadPresentationById {
    suspend operator fun invoke(presentationProcessById: PresentationId): Presentation?
}