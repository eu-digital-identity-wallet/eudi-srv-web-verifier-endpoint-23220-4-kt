package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence

import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadIncompletePresentationsOlderThan
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId
import eu.europa.ec.eudi.verifier.endpoint.domain.isExpired
import java.util.concurrent.ConcurrentHashMap

/**
 * An in-memory repository for storing [presentations][Presentation]
 */
class PresentationInMemoryRepo(
    private val presentations: ConcurrentHashMap<PresentationId, Presentation> = ConcurrentHashMap()
) {

    val loadPresentationById: LoadPresentationById by lazy {
        LoadPresentationById { presentationId -> presentations[presentationId] }
    }

    val loadPresentationByRequestId: LoadPresentationByRequestId by lazy {
        fun requestId(p: Presentation) = when (p) {
            is Presentation.Requested -> p.requestId
            is Presentation.RequestObjectRetrieved -> p.requestId
            is Presentation.Submitted -> p.requestId
            is Presentation.TimedOut -> null
        }
        LoadPresentationByRequestId { requestId ->
            presentations.values.firstOrNull {
                requestId(it) == requestId
            }
        }
    }

    val loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan by lazy {
        LoadIncompletePresentationsOlderThan { at ->
            presentations.values.toList().filter { it.isExpired(at) }
        }
    }
    val storePresentation: StorePresentation by lazy {
        StorePresentation { presentation -> presentations[presentation.id] = presentation }
    }
}