/*
 * Copyright (c) 2025 European Commission
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

import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.DeletePresentationsInitiatedBefore
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadIncompletePresentationsOlderThan
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationEvents
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import org.springframework.data.redis.core.RedisTemplate
import java.time.Duration
import java.time.temporal.ChronoUnit
import java.util.concurrent.TimeUnit

/**
 * A basic redis persistence repository for storing [presentations][Presentation]
 */
class PresentationRedisRepo(
    private val template: RedisTemplate<String, Any?>,
    maxAge: Duration,
    private val eventLogger: PresentationEventLogger = PresentationEventLogger()
) : PresentationCache {
    companion object {
        const val HASH_KEY_PREFIX = "eudi"
        const val HASH_KEY_PRESENTATIONS = "%s:presentation#%s"
        const val HASH_KEY_PRESENTATION_EVENTS = "%s:presentation#%s:events"
        const val HASH_KEY_REQUESTS = "%s:request#%s"
    }

    val expiration: Pair<Long, TimeUnit> = maxAge.get(ChronoUnit.SECONDS) to TimeUnit.SECONDS

    private fun composePresentationKey(presentationId: TransactionId): String =
        HASH_KEY_PRESENTATIONS.format(HASH_KEY_PREFIX, presentationId.value)

    private fun composePresentationEventsKey(presentationId: TransactionId): String =
        HASH_KEY_PRESENTATION_EVENTS.format(HASH_KEY_PREFIX, presentationId.value)

    private fun composeRequestKey(requestId: RequestId): String =
        HASH_KEY_REQUESTS.format(HASH_KEY_PREFIX, requestId.value)

    override val loadPresentationById: LoadPresentationById by lazy {
        LoadPresentationById { presentationId ->
            //presentations[presentationId]?.presentation
            val key = composePresentationKey(presentationId)

            template.opsForValue().get(key) as? Presentation?
        }
    }

    override val loadPresentationByRequestId: LoadPresentationByRequestId by lazy {
        LoadPresentationByRequestId { requestId ->
            val key = composeRequestKey(requestId)
            val ops = template.opsForValue()

            val presentationId = (ops.get(key) as? TransactionId)

            presentationId?.let { presentationId ->
                loadPresentationById(presentationId)
            }
        }
    }

    override val loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan by lazy {
        LoadIncompletePresentationsOlderThan { at ->
            //presentations.values.map { it.presentation }.toList().filter { it.isExpired(at) }
            listOf() // REDIS will auto expire these keys
        }
    }


    override val storePresentation: StorePresentation by lazy {
        StorePresentation { presentation ->
            val ops = template.opsForValue()
            val presentationKey = composePresentationKey(presentation.id)
            ops.set(presentationKey, presentation)
            template.expire(presentationKey, expiration.first, expiration.second)

            requestId(presentation)?.let { requestId ->
                val requestKey = composeRequestKey(requestId)
                ops.set(requestKey, presentation.id)
                template.expire(requestKey, expiration.first, expiration.second)
            }
        }
    }

    override val loadPresentationEvents: LoadPresentationEvents by lazy {
        LoadPresentationEvents { transactionId ->
            val ops = template.opsForList()
            val key = composePresentationEventsKey(transactionId)

            // start = 0, end -1 ==> implies all
            val events = ops.range(key, 0, -1)?.filterIsInstance<PresentationEvent>()

            checkNotNull(events?.toNonEmptyListOrNull())
        }
    }

    override val publishPresentationEvent: PublishPresentationEvent by lazy {
        PublishPresentationEvent { event ->
            eventLogger.log(event)
            val transactionId = event.transactionId

            checkNotNull(loadPresentationById(transactionId)) {
                "Cannot publish event without a presentation"
            }

            val ops = template.opsForList()
            val key = composePresentationEventsKey(transactionId)

            ops.rightPush(key, event)
            template.expire(key, expiration.first, expiration.second)
        }
    }

    override val deletePresentationsInitiatedBefore: DeletePresentationsInitiatedBefore by lazy {
        DeletePresentationsInitiatedBefore { at ->
            /*presentations.filter { (_, presentationAndEvents) -> presentationAndEvents.presentation.initiatedAt < at }
                .keys
                .onEach { presentations.remove(it) }
                .toList()*/
            // transactions are emptied automatically by Redis
            listOf()
        }
    }
}


