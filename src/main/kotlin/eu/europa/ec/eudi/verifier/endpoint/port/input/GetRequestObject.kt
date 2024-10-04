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

import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.domain.retrieveRequestObject
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.Found
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.InvalidState
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.NotFound
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.SignRequestObject
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.time.Clock

/**
 * Given a [RequestId] it returns a RFC9101 Request Object
 * encoded as JWT, if the [Presentation] is input state [Presentation.Requested].
 * In this case, the [Presentation] is updated to [Presentation.RequestObjectRetrieved]
 * input order to guarantee that only once the Request Object can be retrieved by
 * the wallet
 */
fun interface GetRequestObject {
    suspend operator fun invoke(requestId: RequestId): QueryResponse<Jwt>
}

class GetRequestObjectLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) : GetRequestObject {
    private val logger: Logger = LoggerFactory.getLogger(GetRequestObjectLive::class.java)

    override suspend operator fun invoke(requestId: RequestId): QueryResponse<Jwt> =
        when (val presentation = loadPresentationByRequestId(requestId)) {
            null -> NotFound
            is Presentation.Requested -> found(presentation)
            else -> invalidState(presentation)
        }

    private suspend fun found(presentation: Presentation.Requested): Found<Jwt> {
        suspend fun requestObjectOf(): Pair<Presentation.RequestObjectRetrieved, Jwt> {
            val jwt = signRequestObject(verifierConfig, clock, presentation).getOrThrow()
            val updatedPresentation = presentation.retrieveRequestObject(clock).getOrThrow()
            storePresentation(updatedPresentation)
            return updatedPresentation to jwt
        }

        suspend fun log(p: Presentation.RequestObjectRetrieved, jwt: Jwt) {
            val event = PresentationEvent.RequestObjectRetrieved(p.id, p.requestObjectRetrievedAt, jwt)
            publishPresentationEvent(event)
        }

        val (updatePresentation, jwt) = requestObjectOf()
        log(updatePresentation, jwt)
        return Found(jwt)
    }

    private suspend fun invalidState(presentation: Presentation): InvalidState {
        suspend fun log() {
            val cause = "Presentation should be in Requested state but is in ${presentation.javaClass.simpleName}"
            val event = PresentationEvent.FailedToRetrieveRequestObject(presentation.id, clock.instant(), cause)
            logger.error("$cause ${presentation.id}")
            publishPresentationEvent(event)
        }
        log()
        return InvalidState
    }
}
