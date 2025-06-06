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
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DocumentError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.InvalidDocument
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ParsePemEncodedX509CertificateChain
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.x5cShouldBeTrustedOrNull
import id.walt.mdoc.dataelement.*
import id.walt.mdoc.doc.MDoc
import kotlinx.datetime.atStartOfDayIn
import kotlinx.datetime.toKotlinTimeZone
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import java.time.Clock
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

private val log = LoggerFactory.getLogger(ValidateMsoMdocDeviceResponse::class.java)

/**
 * Indicates the reason why DeviceResponse failed to validate.
 */
@Serializable
internal enum class ValidationFailureErrorTypeTO {
    CannotBeDecoded,
    NotOkDeviceResponseStatus,
    InvalidDocuments,
    InvalidIssuerChain,
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

        fun invalidIssuerChain(): ValidationErrorTO =
            ValidationErrorTO(type = ValidationFailureErrorTypeTO.InvalidIssuerChain)
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
    NoMatchingX5CValidator,
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
 * The details of a validated MSO MDoc document.
 */
@Serializable
internal data class DocumentTO(
    val docType: String,
    val attributes: Map<String, JsonObject> = emptyMap(),
)

/**
 * The outcome of trying to validate a DeviceResponse.
 */
internal sealed interface DeviceResponseValidationResult {
    data class Valid(val documents: JsonArray) : DeviceResponseValidationResult
    data class Invalid(val error: ValidationErrorTO) : DeviceResponseValidationResult
}

/**
 * Tries to validate a value as an MSO MDoc DeviceResponse.
 */
internal class ValidateMsoMdocDeviceResponse(
    private val clock: Clock,
    private val parsePemEncodedX509CertificateChain: ParsePemEncodedX509CertificateChain,
    private val deviceResponseValidatorFactory: (X5CShouldBe?) -> DeviceResponseValidator,
) {
    suspend operator fun invoke(deviceResponse: String, issuerChain: String?): DeviceResponseValidationResult {
        val validator = deviceResponseValidator(issuerChain)
            .getOrElse {
                return DeviceResponseValidationResult.Invalid(ValidationErrorTO.invalidIssuerChain())
            }

        return validator.ensureValid(deviceResponse)
            .fold(
                ifRight = { documents ->
                    DeviceResponseValidationResult.Valid(
                        JsonArray(
                            documents.map {
                                Json.encodeToJsonElement(
                                    it.toDocumentTO(
                                        clock,
                                    ),
                                )
                            },
                        ),
                    )
                },
                ifLeft = { DeviceResponseValidationResult.Invalid(it.toValidationFailureTO()) },
            )
    }

    private fun deviceResponseValidator(issuerChainInPem: String?): Result<DeviceResponseValidator> = runCatching {
        val x5cShouldBe = issuerChainInPem
            ?.let { parsePemEncodedX509CertificateChain.x5cShouldBeTrustedOrNull(it).getOrThrow() }
        deviceResponseValidatorFactory(x5cShouldBe)
    }
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
        DocumentError.NoMatchingX5CShouldBe -> DocumentErrorTO.NoMatchingX5CValidator
    }

private fun MDoc.toDocumentTO(clock: Clock): DocumentTO = DocumentTO(
    docType = docType.value,
    attributes = nameSpaces.associateWith { namespace ->
        buildJsonObject {
            getIssuerSignedItems(namespace).map { item ->
                put(item.elementIdentifier.value, item.elementValue.toJsonElement(clock))
            }
        }
    },
)

@OptIn(ExperimentalEncodingApi::class)
private val base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

@OptIn(ExperimentalEncodingApi::class)
private fun DataElement.toJsonElement(clock: Clock): JsonElement =
    when (this) {
        is BooleanElement -> JsonPrimitive(value)
        is ByteStringElement -> JsonPrimitive(base64.encode(value))
        is DateTimeElement -> {
            val epoch = value.toEpochMilliseconds()
            JsonPrimitive(epoch)
        }

        is EncodedCBORElement -> JsonPrimitive(base64.encode(value))
        is FullDateElement -> {
            val epoch = value.atStartOfDayIn(clock.zone.toKotlinTimeZone()).toEpochMilliseconds()
            JsonPrimitive(epoch)
        }

        is ListElement -> {
            val values = value.map { it.toJsonElement(clock) }
            JsonArray(values)
        }

        is MapElement -> {
            val values = value.mapKeys { (key, _) -> key.str }.mapValues { (_, value) -> value.toJsonElement(clock) }
            JsonObject(values)
        }

        is NullElement -> JsonNull
        is NumberElement -> JsonPrimitive(value)
        is StringElement -> JsonPrimitive(value)
        is TDateElement -> {
            val epoch = value.toEpochMilliseconds()
            JsonPrimitive(epoch)
        }

        // Other unsupported DataElements
        else -> JsonPrimitive(this::class.java.simpleName)
    }
