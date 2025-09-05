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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc

import arrow.core.Either
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.sdjwt.vc.KtorHttpClientFactory
import eu.europa.ec.eudi.statium.*
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.toJsonObject
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.datetime.toKotlinInstant
import kotlinx.serialization.json.JsonObject

internal data class StatusCheckException(val reason: String, val causedBy: Throwable) : Exception(reason, causedBy)

internal class StatusListTokenValidator(
    private val httpClientFactory: KtorHttpClientFactory,
    private val clock: java.time.Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) {

    suspend fun validate(sdJwtVc: SdJwtAndKbJwt<SignedJWT>, transactionId: TransactionId? = null) {
        sdJwtVc.sdJwt.jwt.statusReference()?.let { statusReference ->
            Either.catch {
                with(getStatus()) {
                    statusReference.currentStatus().getOrThrow()
                }.also {
                    require(it == Status.Valid) { "Attestation status expected to be VALID but is $it" }
                }
            }
                .onLeft { error -> transactionId?.let { logStatusCheckFailed(it, statusReference, error) } }
                .onRight { transactionId?.let { logStatusCheckSuccess(it, statusReference) } }
                .getOrThrow { StatusCheckException("Attestation status check failed, ${it.message}", it) }
        }
    }

    private fun getStatus(): GetStatus {
        val delegateClock = object : Clock {
            override fun now(): Instant = clock.instant().toKotlinInstant()
        }
        val getStatusListToken: GetStatusListToken = GetStatusListToken.usingJwt(
            clock = delegateClock,
            httpClientFactory = httpClientFactory,
            verifyStatusListTokenSignature = VerifyStatusListTokenSignature.Ignore,
        )
        return GetStatus(getStatusListToken)
    }

    private suspend fun logStatusCheckSuccess(transactionId: TransactionId, statusReference: StatusReference) {
        val event = PresentationEvent.AttestationStatusCheckSuccessful(transactionId, clock.instant(), statusReference)
        publishPresentationEvent(event)
    }

    private suspend fun logStatusCheckFailed(transactionId: TransactionId, statusReference: StatusReference, error: Throwable) {
        val event = PresentationEvent.AttestationStatusCheckFailed(transactionId, clock.instant(), statusReference, error.message)
        publishPresentationEvent(event)
    }
}

private fun SignedJWT.statusReference(): StatusReference? {
    val statusElement = jwtClaimsSet.getJSONObjectClaim(TokenStatusListSpec.STATUS) ?: return null
    val statusJsonObject = statusElement.toJsonObject()
    val statusListElement = statusJsonObject[TokenStatusListSpec.STATUS_LIST]
    requireNotNull(statusListElement) {
        "Expected status_list element but not found"
    }
    require(statusListElement is JsonObject) {
        "Malformed status_list element"
    }

    val index = StatusIndex(statusListElement[TokenStatusListSpec.IDX]?.decodeAs<Int>()?.getOrThrow()!!)
    val uri = statusListElement[TokenStatusListSpec.URI]?.decodeAs<String>()!!.getOrThrow()

    return StatusReference(index, uri)
}
