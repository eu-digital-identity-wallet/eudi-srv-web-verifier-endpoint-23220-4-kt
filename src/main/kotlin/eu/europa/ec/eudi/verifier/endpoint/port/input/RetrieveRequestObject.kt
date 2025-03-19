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

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.SignRequestObject
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import java.time.Clock

/**
 * Method used to invoke GetRequestObject.
 */
sealed interface RetrieveRequestObjectMethod {
    data object Get : RetrieveRequestObjectMethod
    data class Post(val walletMetadata: String?, val walletNonce: String?) : RetrieveRequestObjectMethod
}

/**
 * Errors that can be produced by GetRequestObject
 */
sealed interface RetrieveRequestObjectError {
    data object PresentationNotFound : RetrieveRequestObjectError
    data object InvalidState : RetrieveRequestObjectError
    data object InvalidRequestUriMethod : RetrieveRequestObjectError
}

/**
 * Given a [RequestId] it returns a RFC9101 Request Object
 * encoded as JWT, if the [Presentation] is input state [Presentation.Requested].
 * In this case, the [Presentation] is updated to [Presentation.RequestObjectRetrieved]
 * input order to guarantee that only once the Request Object can be retrieved by
 * the wallet
 */
fun interface RetrieveRequestObject {
    suspend operator fun invoke(requestId: RequestId, method: RetrieveRequestObjectMethod): Either<RetrieveRequestObjectError, Jwt>
}

class RetrieveRequestObjectLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) : RetrieveRequestObject {

    override suspend operator fun invoke(
        requestId: RequestId,
        method: RetrieveRequestObjectMethod,
    ): Either<RetrieveRequestObjectError, Jwt> =
        either {
            when (val presentation = loadPresentationByRequestId(requestId)) {
                null -> raise(RetrieveRequestObjectError.PresentationNotFound)
                is Presentation.Requested -> found(presentation, method).bind()
                else -> raise(invalidState(presentation))
            }
        }

    private suspend fun found(
        presentation: Presentation.Requested,
        invocationMethod: RetrieveRequestObjectMethod,
    ): Either<RetrieveRequestObjectError, Jwt> =
        either {
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

            ensure(invocationMethod is RetrieveRequestObjectMethod.Get || RequestUriMethod.Post == presentation.requestUriMethod) {
                RetrieveRequestObjectError.InvalidRequestUriMethod
            }

            val (updatePresentation, jwt) = requestObjectOf()
            log(updatePresentation, jwt)
            jwt
        }

    private suspend fun invalidState(presentation: Presentation): RetrieveRequestObjectError.InvalidState {
        suspend fun log() {
            val cause = "Presentation should be in Requested state but is in ${presentation.javaClass.name}"
            val event = PresentationEvent.FailedToRetrieveRequestObject(presentation.id, clock.instant(), cause)
            publishPresentationEvent(event)
        }
        log()
        return RetrieveRequestObjectError.InvalidState
    }
}
