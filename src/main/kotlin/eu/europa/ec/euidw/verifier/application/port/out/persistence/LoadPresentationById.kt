package eu.europa.ec.euidw.verifier.application.port.out.persistence

import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationId

fun interface LoadPresentationById {
    suspend operator fun invoke(presentationProcessById: PresentationId): Presentation?
}