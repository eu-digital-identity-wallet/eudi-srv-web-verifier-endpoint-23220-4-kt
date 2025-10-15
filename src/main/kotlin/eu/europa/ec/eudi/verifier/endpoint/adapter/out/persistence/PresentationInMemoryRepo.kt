/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence

import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.domain.isExpired
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.DeletePresentationsInitiatedBefore
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadIncompletePresentationsOlderThan
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationEvents
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import java.util.concurrent.ConcurrentHashMap

/**
 * An input-memory repository for storing [presentations][Presentation]
 */
class PresentationInMemoryRepo(
    private val presentations: ConcurrentHashMap<TransactionId, PresentationStoredEntry> = ConcurrentHashMap(),
    private val eventLogger: PresentationEventLogger = PresentationEventLogger()
) : PresentationCache {

    override val loadPresentationById: LoadPresentationById by lazy {
        LoadPresentationById { presentationId -> presentations[presentationId]?.presentation }
    }

    override val loadPresentationByRequestId: LoadPresentationByRequestId by lazy {
        LoadPresentationByRequestId { requestId ->
            presentations.values.map { it.presentation }.firstOrNull {
                requestId(it) == requestId
            }
        }
    }

    override val loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan by lazy {
        LoadIncompletePresentationsOlderThan { at ->
            presentations.values.map { it.presentation }.toList().filter { it.isExpired(at) }
        }
    }

    override val storePresentation: StorePresentation by lazy {
        StorePresentation { presentation ->
            val existing = presentations[presentation.id]
            presentations[presentation.id] =
                existing?.copy(presentation = presentation) ?: PresentationStoredEntry(presentation, null)
        }
    }

    override val loadPresentationEvents: LoadPresentationEvents by lazy {
        LoadPresentationEvents { transactionId ->
            val p = presentations[transactionId]
            if (p == null) null
            else {
                checkNotNull(p.events)
            }
        }
    }

    override val publishPresentationEvent: PublishPresentationEvent by lazy {
        PublishPresentationEvent { event ->
            eventLogger.log(event)
            val transactionId = event.transactionId
            val presentationAndEvent = checkNotNull(presentations[transactionId]) {
                "Cannot publish event without a presentation"
            }
            val presentationEvents = when (val existingEvents = presentationAndEvent.events) {
                null -> nonEmptyListOf(event)
                else -> existingEvents + event
            }
            presentations[transactionId] = presentationAndEvent.copy(events = presentationEvents)
        }
    }

    override val deletePresentationsInitiatedBefore: DeletePresentationsInitiatedBefore by lazy {
        DeletePresentationsInitiatedBefore { at ->
            presentations.filter { (_, presentationAndEvents) -> presentationAndEvents.presentation.initiatedAt < at }
                .keys
                .onEach { presentations.remove(it) }
                .toList()
        }
    }
}
