package eu.europa.ec.euidw.verifier.application.port.out.persistence

import eu.europa.ec.euidw.verifier.domain.Presentation
import java.time.Instant

fun interface LoadIncompletePresentationsOlderThan {

    suspend operator fun invoke(at: Instant): List<Presentation>
}