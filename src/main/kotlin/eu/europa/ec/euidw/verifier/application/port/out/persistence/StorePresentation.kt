package eu.europa.ec.euidw.verifier.application.port.out.persistence

import eu.europa.ec.euidw.verifier.domain.Presentation

/**
 * Stores or updates a [Presentation] to a storage
 */
fun interface StorePresentation {

    suspend operator fun invoke(presentation: Presentation)
}