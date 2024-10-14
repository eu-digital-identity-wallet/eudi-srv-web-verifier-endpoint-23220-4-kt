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
import id.walt.mdoc.doc.MDoc
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

typealias AttributesPerNamespace = Map<String, List<String>>

/**
 * The details of a validated MSO MDoc document.
 */
@Serializable
internal data class DocumentTO(
    val docType: String,
    val attributes: AttributesPerNamespace = emptyMap(),
)

/**
 * The outcome of trying to validate a DeviceResponse.
 */
internal sealed interface DeviceResponseValidationResult {
    data class Valid(val documents: List<DocumentTO>) : DeviceResponseValidationResult
    data class Invalid(val error: ValidationErrorTO) : DeviceResponseValidationResult
}

/**
 * Tries to validate a value as an MSO MDoc DeviceResponse.
 */
internal class ValidateMsoMdocDeviceResponse(
    clock: Clock,
    trustedIssuers: KeyStore?,
) {
    private val defaultValidator: DeviceResponseValidator by lazy {
        val x5cShouldBe = trustedIssuers?.let { X5CShouldBe.fromKeystore(it) } ?: X5CShouldBe.Ignored
        val docValidator = DocumentValidator(
            clock = clock,
            issuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
            validityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
            x5CShouldBe = x5cShouldBe,

        )

        log.info(
            "Created DocumentValidator using: \n\t" +
                "IssuerSignedItemsShouldBe: '${IssuerSignedItemsShouldBe.Verified}', \n\t" +
                "ValidityInfoShouldBe: '${ValidityInfoShouldBe.NotExpired}', and \n\t" +
                "X5CShouldBe '$x5cShouldBe'",
        )
        DeviceResponseValidator(docValidator)
    }

    operator fun invoke(deviceResponse: String): DeviceResponseValidationResult =
        defaultValidator.ensureValid(deviceResponse)
            .fold(
                ifRight = { documents -> DeviceResponseValidationResult.Valid(documents.map { it.toDocumentTO() }) },
                ifLeft = { DeviceResponseValidationResult.Invalid(it.toValidationFailureTO()) },
            )
}

private fun DeviceResponseError.toValidationFailureTO(): ValidationErrorTO =
    when (this) {
        DeviceResponseError.CannotBeDecoded -> ValidationErrorTO.cannotBeDecoded()
        is DeviceResponseError.NotOkDeviceResponseStatus -> ValidationErrorTO.notOkDeviceResponseStatus(status.toInt())
        is DeviceResponseError.InvalidDocuments -> ValidationErrorTO.invalidDocuments(invalidDocuments.map { it.toInvalidDocumentTO() })
    }

private fun InvalidDocument.toInvalidDocumentTO(): InvalidDocumentTO =
    InvalidDocumentTO(index, documentType, errors.map { it.toDocumentErrorTO() })

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

private fun MDoc.toDocumentTO(): DocumentTO = DocumentTO(
    docType = docType.value,
    attributes = nameSpaces.associateWith { namespace -> getIssuerSignedItems(namespace).map { item -> item.elementIdentifier.value } },
)
