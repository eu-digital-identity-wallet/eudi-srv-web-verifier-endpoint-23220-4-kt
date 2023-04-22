package eu.europa.ec.euidw.verifier.adapter.out.persistence

import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationById
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationId
import java.util.concurrent.ConcurrentHashMap

class PresentationInMemoryRepo(private val presentations: ConcurrentHashMap<PresentationId, Presentation> = ConcurrentHashMap()) {

    val loadPresentationById: LoadPresentationById by lazy {
        LoadPresentationById { presentationId ->
            presentations[presentationId]
        }
    }

    val loadPresentationByRequestId: LoadPresentationByRequestId by lazy {
        fun requestId(p: Presentation) = when(p) {
            is Presentation.Requested -> p.requestId
            is Presentation.RequestObjectRetrieved ->p.requestId
            is Presentation.TimedOut -> null
        }
        LoadPresentationByRequestId { requestId->
            presentations.values.firstOrNull { requestId(it) == requestId}
        }
    }

    val storePresentation: StorePresentation by lazy {
        StorePresentation { presentation ->
            presentations[presentation.id]=presentation
        }
    }
}