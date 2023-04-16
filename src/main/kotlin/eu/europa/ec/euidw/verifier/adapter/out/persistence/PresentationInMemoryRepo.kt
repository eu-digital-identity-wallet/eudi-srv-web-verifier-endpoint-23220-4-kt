package eu.europa.ec.euidw.verifier.adapter.out.persistence

import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationById
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


    val storePresentation: StorePresentation by lazy {
        StorePresentation { presentation ->
            presentations[presentation.id]=presentation
        }
    }
}