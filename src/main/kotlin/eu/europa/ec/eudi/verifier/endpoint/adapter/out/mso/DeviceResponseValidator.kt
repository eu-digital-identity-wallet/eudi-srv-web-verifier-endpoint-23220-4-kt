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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.mapOrAccumulate
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import id.walt.mdoc.dataretrieval.DeviceResponse
import id.walt.mdoc.dataretrieval.DeviceResponseStatus
import id.walt.mdoc.doc.MDoc
import java.security.KeyStore
import java.time.Clock

/**
 * An invalid document inside a device response
 */
data class InvalidDocument(
    val index: Int,
    val documentType: String,
    val errors: NonEmptyList<DocumentError>,
)

/**
 * Errors related to device response
 */
sealed interface DeviceResponseError {
    /**
     * Given vp_token cannot be decoded to a device response
     */
    data object CannotDecode : DeviceResponseError

    /**
     * Device response didn't have an OK status
     */
    data class NotOkDeviceResponseStatus(val status: Number) : DeviceResponseError

    /**
     * Invalid documents found within device response
     */
    data class InvalidDocuments(val invalidDocuments: NonEmptyList<InvalidDocument>) : DeviceResponseError
}

class DeviceResponseValidator(
    private val documentValidator: DocumentValidator,
) {

    /**
     * Validates the given verifier presentation
     * It could a vp_token or an element of an array vp_token
     */
    fun ensureValidDocuments(vp: String): Either<DeviceResponseError, List<MDoc>> =
        either {
            val deviceResponse = decode(vp)
            val validDocuments = ensureValidDocuments(deviceResponse).bind()
            validDocuments
        }

    fun ensureValidDocuments(deviceResponse: DeviceResponse): Either<DeviceResponseError, List<MDoc>> =
        either {
            ensureOkStatus(deviceResponse)
            validDocuments(deviceResponse)
        }

    private fun Raise<DeviceResponseError.InvalidDocuments>.validDocuments(deviceResponse: DeviceResponse): List<MDoc> =
        deviceResponse.documents.withIndex().mapOrAccumulate { (index, document) ->
            documentValidator
                .ensureValidDocument(document)
                .mapLeft { documentErrors -> InvalidDocument(index, document.docType.value, documentErrors) }
                .bind()
        }.mapLeft(DeviceResponseError::InvalidDocuments).bind()

    companion object {

        fun fromKeystore(
            clock: Clock,
            validityInfoShouldBe: ValidityInfoShouldBe,
            keyStore: KeyStore,
        ): DeviceResponseValidator {
            val documentValidator = DocumentValidator.fromKeystore(clock, validityInfoShouldBe, keyStore)
            return DeviceResponseValidator(documentValidator)
        }
    }
}

private fun Raise<DeviceResponseError.CannotDecode>.decode(vp: String): DeviceResponse =
    try {
        DeviceResponse.fromCBORBase64URL(vp)
    } catch (t: Throwable) {
        raise(DeviceResponseError.CannotDecode)
    }

private fun Raise<DeviceResponseError.NotOkDeviceResponseStatus>.ensureOkStatus(deviceResponse: DeviceResponse) {
    val status = deviceResponse.status
    ensure(DeviceResponseStatus.OK.status.toInt() == status.value.toInt()) {
        DeviceResponseError.NotOkDeviceResponseStatus(status.value)
    }
}
