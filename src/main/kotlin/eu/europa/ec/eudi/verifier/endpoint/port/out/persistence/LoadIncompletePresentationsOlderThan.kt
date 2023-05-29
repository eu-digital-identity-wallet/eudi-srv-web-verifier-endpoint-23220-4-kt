package eu.europa.ec.eudi.verifier.endpoint.port.out.persistence

import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import java.time.Instant

fun interface LoadIncompletePresentationsOlderThan {

    suspend operator fun invoke(at: Instant): List<Presentation>
}