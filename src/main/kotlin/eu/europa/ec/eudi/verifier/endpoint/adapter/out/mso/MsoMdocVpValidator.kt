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


data class InvalidDocument(
    val index: Int,
    val documentType: String,
    val errors: NonEmptyList<DocumentError>
)

sealed interface MsoMdocVPError {
    data object CannotDecode : MsoMdocVPError
    data class InvalidDeviceResponse(val cause: DeviceResponseError) : MsoMdocVPError
    data class InvalidDocuments(val invalidDocuments: NonEmptyList<InvalidDocument>) : MsoMdocVPError
}

sealed interface DeviceResponseError {

    data class NotOkDeviceResponseStatus(val status: Number) : DeviceResponseError
}


class MsoMdocVpValidator(
    private val documentValidator: MsoMdocDocumentValidator
) {

    /**
     * Validates the given verifier presentation
     * It could a vp_token or an element of an array vp_token
     */
    fun ensureValidDocuments(vp: String): Either<MsoMdocVPError, List<MDoc>> =
        either {
            val deviceResponse = decode(vp)
            val validDocuments = ensureValidDocuments(deviceResponse).bind()
            validDocuments
        }

    fun ensureValidDocuments(deviceResponse: DeviceResponse): Either<MsoMdocVPError, List<MDoc>> =
        either {
            okStatus(deviceResponse)
            validDocuments(deviceResponse)
        }

    private fun Raise<MsoMdocVPError.InvalidDeviceResponse>.okStatus(deviceResponse: DeviceResponse) =
        either { ensureOkStatus(deviceResponse) }.mapLeft(MsoMdocVPError::InvalidDeviceResponse).bind()

    private fun Raise<MsoMdocVPError.InvalidDocuments>.validDocuments(deviceResponse: DeviceResponse): List<MDoc> =
        deviceResponse.documents.withIndex().mapOrAccumulate { (index, document) ->
            validateDocument(index, document)
        }.mapLeft(MsoMdocVPError::InvalidDocuments).bind()

    private fun Raise<InvalidDocument>.validateDocument(index: Int, document: MDoc): MDoc =
        documentValidator
            .ensureValidDocument(document)
            .mapLeft { documentErrors -> InvalidDocument(index, document.docType.value, documentErrors) }
            .bind()

    companion object {

        fun fromKeystore(
            clock: Clock,
            validityInfoOption: ValidityInfoOption,
            keyStore: KeyStore,
        ): MsoMdocVpValidator {
            val documentValidator = MsoMdocDocumentValidator.fromKeystore(clock, validityInfoOption, keyStore)
            return MsoMdocVpValidator(documentValidator)
        }
    }
}

private fun Raise<MsoMdocVPError>.decode(vp: String): DeviceResponse =
    try {
        DeviceResponse.fromCBORBase64URL(vp)
    } catch (t: Throwable) {
        raise(MsoMdocVPError.CannotDecode)
    }

private fun Raise<DeviceResponseError>.ensureOkStatus(deviceResponse: DeviceResponse) {
    val status = deviceResponse.status
    ensure(DeviceResponseStatus.OK.status.toInt() == status.value.toInt()) {
        DeviceResponseError.NotOkDeviceResponseStatus(status.value)
    }
}