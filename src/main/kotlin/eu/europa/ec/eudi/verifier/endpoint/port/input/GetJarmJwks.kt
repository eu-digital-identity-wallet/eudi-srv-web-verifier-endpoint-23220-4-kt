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

import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.jwk
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import java.time.Clock

/**
 * Given a [RequestId] returns the [JWKSet] to be used for JARM.
 */
fun interface GetJarmJwks {
    suspend operator fun invoke(id: RequestId): QueryResponse<JWKSet>
}

internal class GetJarmJwksLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) : GetJarmJwks {

    override suspend fun invoke(id: RequestId): QueryResponse<JWKSet> =
        when (val presentation = loadPresentationByRequestId(id)) {
            null -> NotFound
            is Presentation.RequestObjectRetrieved ->
                when (val jwkSet = presentation.ephemeralEcPubKey()) {
                    null -> presentationWithoutEphemeralKey(presentation)
                    else -> found(presentation, jwkSet)
                }
            else -> invalidState(presentation)
        }

    private fun Presentation.RequestObjectRetrieved.ephemeralEcPubKey(): JWKSet? =
        if (ephemeralEcPrivateKey != null) JWKSet(listOf(ephemeralEcPrivateKey.jwk())).toPublicJWKSet()
        else null

    private suspend fun found(
        p: Presentation.RequestObjectRetrieved,
        jwkSet: JWKSet,
    ): Found<JWKSet> {
        suspend fun log() {
            val jwkSetJson = Json.encodeToJsonElement(jwkSet.toString(true))
            val event = PresentationEvent.JarmJwkSetRetrieved(p.id, clock.instant(), jwkSetJson)
            publishPresentationEvent(event)
        }
        log()
        return Found(jwkSet)
    }

    private suspend fun presentationWithoutEphemeralKey(p: Presentation.RequestObjectRetrieved): InvalidState {
        logFailure(p, "Presentation without ephemeral key. Probably requested for direct_post")
        return InvalidState
    }

    private suspend fun invalidState(p: Presentation): InvalidState {
        val cause = "Presentation should be in Submitted state but is in ${p.javaClass.simpleName}"
        logFailure(p, cause)
        return InvalidState
    }

    private suspend fun logFailure(p: Presentation, cause: String) {
        val event = PresentationEvent.FailedToRetrieveJarmJwkSet(p.id, clock.instant(), cause)
        publishPresentationEvent(event)
    }
}
