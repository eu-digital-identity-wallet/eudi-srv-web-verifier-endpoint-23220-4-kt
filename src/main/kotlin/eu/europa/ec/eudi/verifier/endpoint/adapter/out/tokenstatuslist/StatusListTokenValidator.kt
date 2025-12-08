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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist

import arrow.core.raise.catch
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.statium.*
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.toJsonObject
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.decodeMsoAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock.Companion.asKotlinClock
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.doc.MDoc
import io.ktor.client.*
import kotlinx.serialization.json.JsonObject

data class StatusCheckException(val reason: String, val causedBy: Throwable) : Exception(reason, causedBy)

class StatusListTokenValidator(
    private val httpClient: HttpClient,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) {

    suspend fun validate(sdJwtVc: SdJwtAndKbJwt<SignedJWT>, transactionId: TransactionId?) =
        sdJwtVc.sdJwt.jwt.statusReference()?.validate(transactionId)

    suspend fun validate(mdoc: MDoc, transactionId: TransactionId?) =
        mdoc.statusReference()?.validate(transactionId)

    private suspend fun StatusReference.validate(transactionId: TransactionId?) {
        catch({
            val currentStatus = with(getStatus()) { currentStatus().getOrThrow() }
            require(currentStatus == Status.Valid) { "Attestation status expected to be VALID but is $currentStatus" }
            transactionId?.let { logStatusCheckSuccess(it, this) }
        }) { error ->
            transactionId?.let { logStatusCheckFailed(it, this, error) }
            throw StatusCheckException("Attestation status check failed, ${error.message}", error)
        }
    }

    private fun getStatus(): GetStatus {
        val getStatusListToken: GetStatusListToken = GetStatusListToken.usingJwt(
            clock = clock.asKotlinClock(),
            httpClient = httpClient,
            verifyStatusListTokenSignature = { _, _ ->
                Result.success(Unit)
            },
        )
        return GetStatus(getStatusListToken)
    }

    private suspend fun logStatusCheckSuccess(transactionId: TransactionId, statusReference: StatusReference) {
        val event = PresentationEvent.AttestationStatusCheckSuccessful(transactionId, clock.now(), statusReference)
        publishPresentationEvent(event)
    }

    private suspend fun logStatusCheckFailed(transactionId: TransactionId, statusReference: StatusReference, error: Throwable) {
        val event = PresentationEvent.AttestationStatusCheckFailed(transactionId, clock.now(), statusReference, error.message)
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

private fun MDoc.statusReference(): StatusReference? {
    val mso = decodeMsoAs<MapElement>() ?: return null
    val status = mso.value[MapKey(TokenStatusListSpec.STATUS)]?.let { it as MapElement } ?: return null
    return status.value[MapKey(TokenStatusListSpec.STATUS_LIST)]?.decodeAs<StatusReference>()
}
