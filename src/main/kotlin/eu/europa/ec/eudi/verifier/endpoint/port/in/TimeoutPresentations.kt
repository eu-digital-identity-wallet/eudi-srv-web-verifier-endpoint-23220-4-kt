package eu.europa.ec.eudi.verifier.endpoint.port.`in`

import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadIncompletePresentationsOlderThan
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId
import eu.europa.ec.eudi.verifier.endpoint.domain.timedOut
import java.time.Clock
import java.time.Duration

fun interface TimeoutPresentations {

    suspend operator fun invoke(): List<PresentationId>
}

class TimeoutPresentationsLive(
    private val loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan,
    private val storePresentation: StorePresentation,
    private val maxAge: Duration,
    private val clock: Clock
) : TimeoutPresentations {
    override suspend operator fun invoke(): List<PresentationId> {
        val expireBefore = clock.instant().minusSeconds(maxAge.toSeconds())
        return loadIncompletePresentationsOlderThan(expireBefore).mapNotNull { timeout(it)?.id }
    }

    private suspend fun timeout(presentation: Presentation): Presentation? {
        val timeout = when (presentation) {
            is Presentation.Requested -> presentation.timedOut(clock).getOrNull()
            is Presentation.RequestObjectRetrieved -> presentation.timedOut(clock).getOrNull()
            is Presentation.Submitted -> presentation.timedOut(clock).getOrNull()
            is Presentation.TimedOut -> null
        }
        return timeout?.also { storePresentation(it) }

    }
}