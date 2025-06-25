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
package eu.europa.ec.eudi.verifier.endpoint.domain

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import kotlinx.io.bytestring.decodeToByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encode
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import java.net.URL
import kotlin.contracts.contract

/**
 * Wrapper for a JsonObject that contains Transaction Data.
 */
@JvmInline
value class TransactionData private constructor(val value: JsonObject) {

    val type: String
        get() = value["type"]!!.jsonPrimitive.content

    val credentialIds: NonEmptyList<String>
        get() = value["credential_ids"]!!
            .jsonArray
            .map { it.jsonPrimitive.content }
            .toNonEmptyListOrNull()!!

    val hashAlgorithms: NonEmptyList<String>?
        get() = value["transaction_data_hashes_alg"]
            ?.jsonArray
            ?.map { it.jsonPrimitive.content }
            ?.let {
                it.toNonEmptyListOrNull()!!
            }

    val base64Url: String
        get() {
            val serialized = jsonSupport.encodeToString(value)
            val decoded = serialized.encodeToByteString()
            val encoded = base64UrlNoPadding.encode(decoded)
            return encoded
        }

    inline fun <reified T> decodeAs(
        deserializer: DeserializationStrategy<T> = serializer(),
        json: Json = Json.Default,
    ): T = json.decodeFromJsonElement(deserializer, value)

    companion object {

        private fun validate(value: JsonObject): Either<Throwable, TransactionData> = Either.catch {
            val type = value["type"]
            require(type.isNonEmptyString()) {
                "'type' is required and must not be a non-empty string"
            }

            val credentialIds = value["credential_ids"]
            require(credentialIds.isNonEmptyArray() && credentialIds.all { it.isNonEmptyString() }) {
                "'credential_ids' is required and must be a non-empty array of non-empty strings"
            }

            value["transaction_data_hashes_alg"]?.let { hashAlgorithms ->
                require(hashAlgorithms.isNonEmptyArray() && hashAlgorithms.all { it.isNonEmptyString() }) {
                    "'transaction_data_hashes_alg' if present must be a non-empty array of non-empty strings"
                }
            }

            TransactionData(value)
        }

        operator fun invoke(
            type: String,
            credentialIds: NonEmptyList<String>,
            hashAlgorithms: NonEmptyList<String>? = null,
            builder: JsonObjectBuilder.() -> Unit = {},
        ): Either<Throwable, TransactionData> {
            val value = buildJsonObject {
                builder()

                put("type", type)
                putJsonArray("credential_ids") {
                    addAll(credentialIds)
                }
                hashAlgorithms?.let { hashAlgorithms ->
                    putJsonArray("transaction_data_hashes_alg") {
                        addAll(hashAlgorithms)
                    }
                }
            }
            return validate(value)
        }

        fun validate(
            unvalidated: JsonObject,
            validCredentialIds: List<String>,
        ): Either<Throwable, TransactionData> = Either.catch {
            val transactionData = validate(unvalidated).getOrThrow()
            require(validCredentialIds.containsAll(transactionData.credentialIds)) {
                "invalid 'credential_ids'"
            }
            transactionData
        }

        fun fromBase64Url(
            base64Url: String,
        ): Either<Throwable, TransactionData> = Either.catch {
            val decoded = base64UrlNoPadding.decodeToByteString(base64Url)
            val serialized = decoded.decodeToString()
            val json = jsonSupport.decodeFromString<JsonObject>(serialized)
            validate(json).getOrThrow()
        }
    }
}

/**
 * Checks if this [JsonElement] is a [JsonPrimitive] that is a non-empty string.
 */
private fun JsonElement?.isNonEmptyString(): Boolean {
    contract {
        returns(true) implies(this@isNonEmptyString is JsonPrimitive)
    }

    return this is JsonPrimitive && this.isString && this.content.isNotEmpty()
}

/**
 * Checks if this [JsonElement] is a non-empty [JsonArray].
 */
private fun JsonElement?.isNonEmptyArray(): Boolean {
    contract {
        returns(true) implies(this@isNonEmptyArray is JsonArray)
    }

    return this is JsonArray && this.isNotEmpty()
}

/**
 * Identifier of the Signature to be created.
 */
@Serializable
@JvmInline
internal value class SignatureQualifier(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value

    companion object {
        val EuEidasQes: SignatureQualifier
            get() = SignatureQualifier("eu_eidas_qes")

        val EuEidasAes: SignatureQualifier
            get() = SignatureQualifier("eu_eidas_aes")

        val EuEidasAesQc: SignatureQualifier
            get() = SignatureQualifier("eu_eidas_aesqc")

        val EuEidasQeSeal: SignatureQualifier
            get() = SignatureQualifier("eu_eidas_qeseal")

        val EuEidasAeSeal: SignatureQualifier
            get() = SignatureQualifier("eu_eidas_aeseal")

        val EuEidasAeSealQc: SignatureQualifier
            get() = SignatureQualifier("eu_eidas_aesealqc")

        val ZaEctaAes: SignatureQualifier
            get() = SignatureQualifier("za_ecta_aes")

        val ZaEctaOes: SignatureQualifier
            get() = SignatureQualifier("za_ecta_oes")
    }
}

/**
 * Unique identifier for a Credential.
 */
@Serializable
@JvmInline
internal value class CredentialId(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * A label.
 */
@Serializable
@JvmInline
internal value class Label(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * OID Hash Algorithm.
 */
@Serializable
@JvmInline
internal value class HashAlgorithmOID(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * [KSerializer] for [URL]. Serializes its value as a string using [URL.toExternalForm].
 */
internal object URLStringSerializer : KSerializer<URL> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("URLString", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: URL) {
        encoder.encodeString(value.toExternalForm())
    }

    override fun deserialize(decoder: Decoder): URL = URL(decoder.decodeString())
}

/**
 * Access mode.
 */
@Serializable
@JvmInline
internal value class AccessMode(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value

    companion object {
        val Public: AccessMode
            get() = AccessMode("public")

        val OneTimePassword: AccessMode
            get() = AccessMode("OTP")

        val BasicAuthentication: AccessMode
            get() = AccessMode("Basic_Auth")

        val DigestAuthentication: AccessMode
            get() = AccessMode("Digest_Auth")

        val OAuth20: AccessMode
            get() = AccessMode("OAuth_20")
    }
}

/**
 * A single use password.
 */
@Serializable
@JvmInline
internal value class OneTimePassword(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * Access method for a document to be signed.
 */
@Serializable
internal data class DocumentAccessMethod(

    @SerialName("document_access_mode")
    @Required
    val accessMode: AccessMode,

    @SerialName("oneTimePassword")
    val oneTimePassword: OneTimePassword? = null,

) {
    init {
        if (AccessMode.OneTimePassword == accessMode) {
            requireNotNull(oneTimePassword) { "'oneTimePassword' is required when 'document_access_mode' is 'OTP'." }
        }
    }
}

/**
 * Data of a document to be signed.
 */
@Serializable
internal data class DocumentDigest(

    @SerialName("label")
    @Required
    val label: Label,

    @SerialName("hash")
    val hash: String? = null,

    @SerialName("hashAlgorithmOID")
    val hashAlgorithm: HashAlgorithmOID? = null,

    @SerialName("documentLocation_uri")
    @Serializable(with = URLStringSerializer::class)
    val documentLocation: URL? = null,

    @SerialName("documentLocation_method")
    val documentAccessMethod: DocumentAccessMethod? = null,

    @SerialName("DTBS/R")
    val dataToBeSignedRepresentation: String? = null,

    @SerialName("DTBS/RHashAlgorithmOID")
    val dataToBeSignedRepresentationHashAlgorithm: HashAlgorithmOID? = null,

) {
    init {
        require((null == hash && null == hashAlgorithm) || (null != hash && null != hashAlgorithm)) {
            "either provide both 'hash' and 'hashAlgorithmOID', or none."
        }
        require(
            (null == dataToBeSignedRepresentation && null == dataToBeSignedRepresentationHashAlgorithm) ||
                (null != dataToBeSignedRepresentation && null != dataToBeSignedRepresentationHashAlgorithm),
        ) {
            "either provide both 'DTBS/R' and 'DTBS/RHashAlgorithmOID', or none."
        }
        require(
            (null == documentLocation && null == documentAccessMethod) ||
                (null != documentLocation && null != documentAccessMethod),
        ) {
            "either provide both 'documentLocation_uri' and 'documentLocation_method', or none."
        }
        require(
            null != hash || null != dataToBeSignedRepresentation,
        ) { "either 'hash', or 'dataToBeSignedRepresentation' must be present." }
    }
}

/**
 * Unique identifier of a signing process.
 */
@Serializable
@JvmInline
internal value class ProcessId(val value: String) {
    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value
}

/**
 * Transaction Data for Qualified Electronic Signature (QES) Authorization.
 */
@Serializable
internal data class QesAuthorization(
    @SerialName("type")
    @Required
    val type: String,

    @SerialName("credential_ids")
    @Required
    val credentialIds: List<String>,

    @SerialName("transaction_data_hashes_alg")
    val hashAlgorithms: List<String>? = null,

    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,

    @SerialName("credentialID")
    val credentialId: CredentialId? = null,

    @SerialName("documentDigests")
    @Required
    val documentDigests: List<DocumentDigest>,

    @SerialName("processID")
    val processId: ProcessId? = null,

) {
    init {
        require(TYPE == type) { "Expected 'type' to be '$TYPE'. Was: '$type'." }
        require(credentialIds.isNotEmpty()) { "'credential_ids' must not be empty." }
        require(null != credentialId || null != signatureQualifier) {
            "either 'credentialID', or 'signatureQualifier' must be present."
        }
        require(documentDigests.isNotEmpty()) { "'documentDigests' must not be empty." }
    }

    companion object {
        const val TYPE = "qes_authorization"
    }
}

/**
 * Transaction Data for Qualified Certification Creation Acceptance.
 */
@Serializable
internal data class QCertCreationAcceptance(
    @SerialName("type")
    @Required
    val type: String,

    @SerialName("credential_ids")
    @Required
    val credentialIds: List<String>,

    @SerialName("transaction_data_hashes_alg")
    val hashAlgorithms: List<String>? = null,

    @SerialName("QC_terms_conditions_uri")
    @Required
    @Serializable(with = URLStringSerializer::class)
    val termsAndConditions: URL,

    @SerialName("QC_hash")
    @Required
    val documentHash: String,

    @SerialName("QC_hashAlgorithmOID")
    @Required
    val hashAlgorithm: HashAlgorithmOID,

) {
    init {
        require(TYPE == type) { "Expected 'type' to be '$TYPE'. Was: '$type'." }
        require(credentialIds.isNotEmpty()) { "'credential_ids' must not be empty." }
    }

    companion object {
        const val TYPE = "qcert_creation_acceptance"
    }
}
