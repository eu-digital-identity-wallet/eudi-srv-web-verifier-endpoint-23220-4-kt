package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence

import arrow.core.NonEmptyList
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent

data class PresentationStoredEntry(
    val presentation: Presentation,
    val events: NonEmptyList<PresentationEvent>?,
)
