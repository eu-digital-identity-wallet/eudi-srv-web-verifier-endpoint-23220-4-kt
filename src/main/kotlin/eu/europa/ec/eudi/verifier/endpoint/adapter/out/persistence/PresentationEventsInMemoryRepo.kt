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

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationEvents
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import kotlinx.coroutines.sync.Mutex
import java.util.concurrent.ConcurrentHashMap

class PresentationEventsInMemoryRepo(
    private val logs: ConcurrentHashMap<TransactionId, NonEmptyList<PresentationEvent>> = ConcurrentHashMap(),
) {

    private val mutex = Mutex()

    val loadPresentationEvents: LoadPresentationEvents by lazy {
        LoadPresentationEvents { transactionId -> logs[transactionId] }
    }

    val publishPresentationEvent: PublishPresentationEvent by lazy {
        PublishPresentationEvent { event ->
            val transactionId = event.transactionId
            val presentationEvents = when (val existingEvents = logs[transactionId]) {
                null -> nonEmptyListOf(event)
                else -> existingEvents + event
            }
            logs[transactionId] = presentationEvents
        }
    }
}
