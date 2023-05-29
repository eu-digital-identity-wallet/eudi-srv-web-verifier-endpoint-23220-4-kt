package eu.europa.ec.eudi.verifier.endpoint.port.out.persistence

import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation

/**
 * Stores or updates a [Presentation] to a storage
 */
fun interface StorePresentation {

    suspend operator fun invoke(presentation: Presentation)
}