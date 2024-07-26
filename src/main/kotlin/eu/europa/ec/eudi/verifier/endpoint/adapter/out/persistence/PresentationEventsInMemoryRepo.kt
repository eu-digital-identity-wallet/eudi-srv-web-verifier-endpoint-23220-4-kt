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
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap

private val logger = LoggerFactory.getLogger("EVENTS")

class PresentationEventsInMemoryRepo(
    private val logs: ConcurrentHashMap<TransactionId, NonEmptyList<PresentationEvent>> = ConcurrentHashMap(),
) {

    val loadPresentationEvents: LoadPresentationEvents by lazy {
        LoadPresentationEvents { transactionId -> logs[transactionId] }
    }

    val publishPresentationEvent: PublishPresentationEvent by lazy {
        PublishPresentationEvent { event ->
            log(event)
            val transactionId = event.transactionId
            val presentationEvents = when (val existingEvents = logs[transactionId]) {
                null -> nonEmptyListOf(event)
                else -> existingEvents + event
            }
            logs[transactionId] = presentationEvents
        }
    }
}

private fun log(e: PresentationEvent) {
    fun txt(s: String) = "$s - tx: ${e.transactionId.value}"
    fun warn(s: String) = logger.warn(txt(s))
    fun info(s: String) = logger.info(txt(s))
    when (e) {
        is PresentationEvent.VerifierFailedToGetWalletResponse -> warn("Verifier failed to retrieve wallet response. Cause ${e.cause}")
        is PresentationEvent.FailedToRetrieveJarmJwkSet -> warn("Verifier failed to retrieve JARM JWKS. Cause ${e.cause}")
        is PresentationEvent.FailedToRetrievePresentationDefinition -> warn(
            "Verifier failed to retrieve presentation definition. Cause ${e.cause}",
        )
        is PresentationEvent.WalletFailedToPostResponse -> warn("Wallet failed to post response. Cause ${e.cause}")
        is PresentationEvent.FailedToRetrieveRequestObject -> warn("Wallet failed to retrieve request object. Cause ${e.cause}")
        is PresentationEvent.PresentationExpired -> info("Expired presentation")
        is PresentationEvent.JarmJwkSetRetrieved -> info("Wallet retrieved JARM JWKS")
        is PresentationEvent.PresentationDefinitionRetrieved -> info("Wallet retrieved presentation definition")
        is PresentationEvent.RequestObjectRetrieved -> info("Wallet retrieved Request Object")
        is PresentationEvent.TransactionInitialized -> info("Verifier initialized transaction")
        is PresentationEvent.VerifierGotWalletResponse -> info("Verifier retrieved wallet response")
        is PresentationEvent.WalletResponsePosted -> info("Wallet posted response")
    }
}
