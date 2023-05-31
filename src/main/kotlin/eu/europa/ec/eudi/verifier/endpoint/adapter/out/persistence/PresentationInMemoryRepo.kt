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

import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId
import eu.europa.ec.eudi.verifier.endpoint.domain.isExpired
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadIncompletePresentationsOlderThan
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import java.util.concurrent.ConcurrentHashMap

/**
 * An input-memory repository for storing [presentations][Presentation]
 */
class PresentationInMemoryRepo(
    private val presentations: ConcurrentHashMap<PresentationId, Presentation> = ConcurrentHashMap(),
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
