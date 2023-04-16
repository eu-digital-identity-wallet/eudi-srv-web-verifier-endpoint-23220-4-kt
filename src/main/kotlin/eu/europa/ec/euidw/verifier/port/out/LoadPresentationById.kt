package eu.europa.ec.euidw.verifier.port.out

import eu.europa.ec.euidw.verifier.Presentation
import eu.europa.ec.euidw.verifier.PresentationId

fun interface LoadPresentationById {
    suspend operator fun invoke(presentationProcessById: PresentationId): Presentation?
}