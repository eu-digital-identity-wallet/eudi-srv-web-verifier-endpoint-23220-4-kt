package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence

import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.DeletePresentationsInitiatedBefore
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadIncompletePresentationsOlderThan
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationEvents
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation

interface PresentationCache {
    val loadPresentationById: LoadPresentationById
    val loadPresentationByRequestId: LoadPresentationByRequestId
    val loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan
    val storePresentation: StorePresentation
    val loadPresentationEvents: LoadPresentationEvents
    val publishPresentationEvent: PublishPresentationEvent
    val deletePresentationsInitiatedBefore: DeletePresentationsInitiatedBefore

    fun requestId(p: Presentation) = when (p) {
        is Presentation.Requested -> p.requestId
        is Presentation.RequestObjectRetrieved -> p.requestId
        is Presentation.Submitted -> p.requestId
        is Presentation.TimedOut -> null
    }


}
