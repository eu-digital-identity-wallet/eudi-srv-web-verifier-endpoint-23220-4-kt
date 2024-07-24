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

import arrow.core.NonEmptyList
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationEvents
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.time.Clock

@Serializable
data class PresentationEventsTO(
    @SerialName("transaction_id") val transactionId: String,
    val timestamp: Long,
    val events: List<JsonObject>,
)

fun interface GetPresentationEvents {
    suspend operator fun invoke(transactionId: TransactionId): QueryResponse<PresentationEventsTO>
}

class GetPresentationEventsLive(
    private val clock: Clock,
    private val loadPresentationById: LoadPresentationById,
    private val loadPresentationEvents: LoadPresentationEvents,
) : GetPresentationEvents {
    override suspend fun invoke(
        transactionId: TransactionId,
    ): QueryResponse<PresentationEventsTO> = coroutineScope {
        val events = when (val presentation = loadPresentationById(transactionId)) {
            null -> null
            else -> loadPresentationEvents(transactionId)
        }
        events
            ?.let { es -> QueryResponse.Found(PresentationEventsTO(transactionId, clock, es)) }
            ?: QueryResponse.NotFound
    }
}

private operator fun PresentationEventsTO.Companion.invoke(
    transactionId: TransactionId,
    clock: Clock,
    events: NonEmptyList<PresentationEvent>,
) =
    PresentationEventsTO(
        transactionId = transactionId.value,
        timestamp = clock.instant().toEpochMilli(),
        events = events.map { event ->
            require(event.transactionId == transactionId)
            toTransferObject(event)
        }.toList(),
    )

private fun toTransferObject(event: PresentationEvent) = buildJsonObject {
    put("timestamp", event.timestamp.toEpochMilli())
    putEventNameAndActor(event)
    when (event) {
        is PresentationEvent.TransactionInitialized -> {
            put("response", event.response.json())
        }

        is PresentationEvent.PresentationDefinitionRetrieved -> {
        }

        is PresentationEvent.PresentationExpired -> {
        }

        is PresentationEvent.RequestObjectRetrieved -> {
        }

        is PresentationEvent.VerifierGotWalletResponse -> {
            put("wallet_response", event.walletResponse.json())
        }

        is PresentationEvent.WalletResponsePosted -> {
        }
    }
}

@Serializable
private enum class Actor {
    Verifier,
    Wallet,
    VerifierEndPoint,
}

private fun JsonObjectBuilder.putEventNameAndActor(e: PresentationEvent) {
    val (eventName, actor) = when (e) {
        is PresentationEvent.PresentationDefinitionRetrieved -> "Presentation definition retrieved" to Actor.Wallet
        is PresentationEvent.PresentationExpired -> "Presentation expired" to Actor.VerifierEndPoint
        is PresentationEvent.RequestObjectRetrieved -> "Request object retrieved" to Actor.Wallet
        is PresentationEvent.TransactionInitialized -> "Transaction initialized" to Actor.Verifier
        is PresentationEvent.VerifierGotWalletResponse -> "Verifier got wallet response" to Actor.Verifier
        is PresentationEvent.WalletResponsePosted -> "Wallet response posted" to Actor.Wallet
    }
    put("event", eventName)
    put("actor", actor.json())
}

private inline fun <reified A> A.json() = Json.encodeToJsonElement(this)
