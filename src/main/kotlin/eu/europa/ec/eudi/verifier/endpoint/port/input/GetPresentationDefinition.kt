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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.presentationDefinitionOrNull
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import kotlinx.coroutines.coroutineScope
import java.time.Clock

/**
 * Given a [RequestId] returns the [PresentationDefinition] if
 * the [Presentation] is input state [Presentation.RequestObjectRetrieved] and if
 * it is related to verifiable credentials presentation
 */
fun interface GetPresentationDefinition {
    suspend operator fun invoke(requestId: RequestId): QueryResponse<PresentationDefinition>
}

class GetPresentationDefinitionLive(
    private val clock: Clock,
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val publishPresentationEvent: PublishPresentationEvent,
) : GetPresentationDefinition {
    override suspend fun invoke(requestId: RequestId): QueryResponse<PresentationDefinition> = coroutineScope {
        suspend fun foundOrInvalid(p: Presentation) =
            p.type.presentationDefinitionOrNull?.let { pd ->
                logRetrieval(p, pd)
                Found(pd)
            } ?: InvalidState

        when (val presentation = loadPresentationByRequestId(requestId)) {
            null -> NotFound
            is Presentation.RequestObjectRetrieved -> foundOrInvalid(presentation)
            else -> InvalidState
        }
    }

    private suspend fun logRetrieval(p: Presentation, pd: PresentationDefinition) {
        val event = PresentationEvent.PresentationDefinitionRetrieved(p.id, clock.instant(), pd)
        publishPresentationEvent(event)
    }
}
