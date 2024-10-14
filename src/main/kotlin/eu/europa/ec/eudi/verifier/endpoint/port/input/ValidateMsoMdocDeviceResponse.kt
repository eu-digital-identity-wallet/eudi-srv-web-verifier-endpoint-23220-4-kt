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
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import java.security.KeyStore
import java.time.Clock

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
internal data class ValidationErrorTO(
    val type: ValidationFailureErrorTypeTO,
    val deviceResponseStatus: Int? = null,
    val invalidDocuments: List<InvalidDocumentTO>? = null,
) {
    companion object {
        fun cannotBeDecoded(): ValidationErrorTO =
            ValidationErrorTO(type = ValidationFailureErrorTypeTO.CannotBeDecoded)

        fun notOkDeviceResponseStatus(deviceResponseStatus: Int): ValidationErrorTO =
            ValidationErrorTO(
                type = ValidationFailureErrorTypeTO.NotOkDeviceResponseStatus,
                deviceResponseStatus = deviceResponseStatus,
            )

        fun invalidDocuments(invalidDocuments: NonEmptyList<InvalidDocumentTO>): ValidationErrorTO =
            ValidationErrorTO(
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
    data class Valid(val numberOfDocuments: Int) : DeviceResponseValidationResult
    data class Invalid(val error: ValidationErrorTO) : DeviceResponseValidationResult
}

/**
 * Tries to validate a vp_token as an MsoMdoc DeviceResponse.
 */
internal class ValidateMsoMdocDeviceResponse(
    private val clock: Clock,
    private val trustedIssuers: KeyStore?,
) {

    private val defaultValidator: DeviceResponseValidator by lazy {
        val x5cShouldBe = trustedIssuers?.let { X5CShouldBe.fromKeystore(it) } ?: X5CShouldBe.Ignored

        val docValidator = DocumentValidator(
            clock = clock,
            issuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
            validityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
            x5CShouldBe = x5cShouldBe,

        )
        // Log here the options
        DeviceResponseValidator(docValidator)
    }

    operator fun invoke(vpToken: String): DeviceResponseValidationResult =
        defaultValidator.ensureValid(vpToken)
            .fold(
                ifRight = { docs -> DeviceResponseValidationResult.Valid(docs.size) },
                ifLeft = { DeviceResponseValidationResult.Invalid(it.toValidationFailureTO()) },
            )
}

/**
 * Converts this [DeviceResponseError] to a [ValidationErrorTO].
 */
private fun DeviceResponseError.toValidationFailureTO(): ValidationErrorTO =
    when (this) {
        DeviceResponseError.CannotBeDecoded -> ValidationErrorTO.cannotBeDecoded()
        is DeviceResponseError.NotOkDeviceResponseStatus -> ValidationErrorTO.notOkDeviceResponseStatus(status.toInt())
        is DeviceResponseError.InvalidDocuments -> ValidationErrorTO.invalidDocuments(invalidDocuments.map { it.toInvalidDocumentTO() })
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
