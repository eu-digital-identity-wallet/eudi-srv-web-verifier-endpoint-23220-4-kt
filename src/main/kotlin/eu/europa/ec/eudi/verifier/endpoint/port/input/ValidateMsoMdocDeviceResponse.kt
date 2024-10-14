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
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DocumentError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.InvalidDocument
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(ValidateMsoMdocDeviceResponse::class.java)

/**
 * Indicates the reason why DeviceResponse failed to validate.
 */
@Serializable
internal enum class ValidationFailureErrorTypeTO {
    CannotBeDecoded,
    NotOkDeviceResponseStatus,
    InvalidDocuments,
}

/**
 * Details abouts the reason why DeviceResponse failed to validate.
 */
@Serializable
internal data class ValidationFailureTO(
    val type: ValidationFailureErrorTypeTO,
    val deviceResponseStatus: Int? = null,
    val invalidDocuments: List<InvalidDocumentTO>? = null,
) {
    companion object {
        fun cannotBeDecoded(): ValidationFailureTO =
            ValidationFailureTO(type = ValidationFailureErrorTypeTO.CannotBeDecoded)

        fun notOkDeviceResponseStatus(deviceResponseStatus: Int): ValidationFailureTO =
            ValidationFailureTO(
                type = ValidationFailureErrorTypeTO.NotOkDeviceResponseStatus,
                deviceResponseStatus = deviceResponseStatus,
            )

        fun invalidDocuments(invalidDocuments: NonEmptyList<InvalidDocumentTO>): ValidationFailureTO =
            ValidationFailureTO(
                type = ValidationFailureErrorTypeTO.InvalidDocuments,
                invalidDocuments = invalidDocuments,
            )
    }
}

/**
 * Indicates the reason why an MDoc document withing a DeviceResponse failed to validate.
 */
@Serializable
internal enum class DocumentErrorTO {
    MissingValidityInfo,
    ExpiredValidityInfo,
    IssuerKeyIsNotEC,
    InvalidIssuerSignature,
    X5CNotTrusted,
    DocumentTypeNotMatching,
    InvalidIssuerSignedItems,
}

/**
 * Details about the reason why an MDoc document withing a DeviceResponse failed to validate.
 */
@Serializable
internal data class InvalidDocumentTO(
    val index: Int,
    val documentType: String,
    val errors: List<DocumentErrorTO>,
)

/**
 * The outcome of trying to validate a DeviceResponse.
 */
internal sealed interface DeviceResponseValidationResult {
    data object ValidationSuccess : DeviceResponseValidationResult
    data class ValidationFailure(val reason: ValidationFailureTO) : DeviceResponseValidationResult
    data class UnexpectedError(val error: Exception) : DeviceResponseValidationResult

    companion object {
        fun validationSuccess(): ValidationSuccess = ValidationSuccess
        fun validationFailure(reason: ValidationFailureTO): ValidationFailure = ValidationFailure(reason)
        fun unexpectedError(error: Exception): UnexpectedError = UnexpectedError(error)
    }
}

/**
 * Tries to validate a vp_token as an MsoMdoc DeviceResponse.
 */
internal class ValidateMsoMdocDeviceResponse(
    private val deviceResponseValidator: DeviceResponseValidator,
) {

    operator fun invoke(vpToken: String): DeviceResponseValidationResult =
        try {
            deviceResponseValidator.ensureValid(vpToken)
                .fold(
                    ifRight = { DeviceResponseValidationResult.validationSuccess() },
                    ifLeft = { DeviceResponseValidationResult.validationFailure(it.toValidationFailureTO()) },
                )
        } catch (error: Exception) {
            log.error("Unexpected error while trying to validate DeviceResponse", error)
            DeviceResponseValidationResult.unexpectedError(error)
        }
}

/**
 * Converts this [DeviceResponseError] to a [ValidationFailureTO].
 */
private fun DeviceResponseError.toValidationFailureTO(): ValidationFailureTO =
    when (this) {
        DeviceResponseError.CannotBeDecoded -> ValidationFailureTO.cannotBeDecoded()
        is DeviceResponseError.NotOkDeviceResponseStatus -> ValidationFailureTO.notOkDeviceResponseStatus(status.toInt())
        is DeviceResponseError.InvalidDocuments -> ValidationFailureTO.invalidDocuments(invalidDocuments.map { it.toInvalidDocumentTO() })
    }

/**
 * Converts this [InvalidDocument] to a [InvalidDocumentTO].
 */
private fun InvalidDocument.toInvalidDocumentTO(): InvalidDocumentTO =
    InvalidDocumentTO(index, documentType, errors.map { it.toDocumentErrorTO() })

/**
 * Converts this [DocumentError] to a [DocumentErrorTO].
 */
private fun DocumentError.toDocumentErrorTO(): DocumentErrorTO =
    when (this) {
        DocumentError.MissingValidityInfo -> DocumentErrorTO.MissingValidityInfo
        is DocumentError.ExpiredValidityInfo -> DocumentErrorTO.ExpiredValidityInfo
        DocumentError.IssuerKeyIsNotEC -> DocumentErrorTO.IssuerKeyIsNotEC
        DocumentError.InvalidIssuerSignature -> DocumentErrorTO.InvalidIssuerSignature
        is DocumentError.X5CNotTrusted -> DocumentErrorTO.X5CNotTrusted
        DocumentError.DocumentTypeNotMatching -> DocumentErrorTO.DocumentTypeNotMatching
        DocumentError.InvalidIssuerSignedItems -> DocumentErrorTO.InvalidIssuerSignedItems
    }
