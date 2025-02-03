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

import com.eygraber.uri.Uri
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.Base64URLStringSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.net.URL

/**
 * Base structure for Transaction Data as defined by OpenId4VP.
 */
internal interface TransactionData {

    @SerialName("type")
    @Required
    val type: String

    @SerialName("credential_ids")
    @Required
    val credentialIds: List<String>

    @SerialName("transaction_data_hashes_alg")
    val hashAlgorithms: List<String>?
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
 * A URL for a Document.
 */
@Serializable
@JvmInline
internal value class DocumentUrl(
    @Serializable(with = URLStringSerializer::class) val value: URL,
) {
    init {
        val uri = Uri.parse(value.toExternalForm())
        require(!uri.getQueryParameter("hash").isNullOrEmpty()) {
            "a document url must contain a non-empty 'hash' query parameter"
        }
    }

    override fun toString(): String = value.toExternalForm()
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
    val oneTimePassword: OneTimePassword?,

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
    @Serializable(with = Base64URLStringSerializer::class)
    val hash: Base64URL?,

    @SerialName("hashAlgorithmOID")
    val hashAlgorithm: HashAlgorithmOID?,

    @SerialName("documentLocation_uri")
    val documentLocation: DocumentUrl?,

    @SerialName("documentLocation_method")
    val documentAccessMethod: DocumentAccessMethod?,

    @SerialName("DTBS/R")
    @Serializable(with = Base64URLStringSerializer::class)
    val dataToBeSigned: Base64URL?,

    @SerialName("DTBS/RHashAlgorithmOID")
    val dataToBeSignedHashAlgorithm: HashAlgorithmOID?,

) {
    init {
        require((null == hash && null == hashAlgorithm) || (null != hash && null != hashAlgorithm)) {
            "either provide both 'hash' and 'hashAlgorithmOID', or none."
        }
        require(
            (null == dataToBeSigned && null == dataToBeSignedHashAlgorithm) ||
                (null != dataToBeSigned && null != dataToBeSignedHashAlgorithm),
        ) {
            "either provide both 'DTBS/R' and 'DTBS/RHashAlgorithmOID', or none."
        }
        require(
            (null == documentLocation && null == documentAccessMethod) ||
                (null != documentLocation && null != documentAccessMethod),
        ) {
            "either provide both 'documentLocation_uri' and 'documentLocation_method', or none."
        }
        require(null != hash || null != dataToBeSigned) { "either 'hash', or 'dataToBeSigned' must be present." }
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
    override val type: String,

    @SerialName("credential_ids")
    @Required
    override val credentialIds: List<String>,

    @SerialName("transaction_data_hashes_alg")
    override val hashAlgorithms: List<String>?,

    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier?,

    @SerialName("credentialID")
    val credentialId: CredentialId?,

    @SerialName("documentDigests")
    val documentDigests: List<DocumentDigest>,

    @SerialName("processID")
    val processId: ProcessId?,

) : TransactionData {
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
    override val type: String,

    @SerialName("credential_ids")
    @Required
    override val credentialIds: List<String>,

    @SerialName("transaction_data_hashes_alg")
    override val hashAlgorithms: List<String>?,

    @SerialName("QC_terms_conditions_uri")
    @Required
    @Serializable(with = URLStringSerializer::class)
    val termsAndConditions: URL,

    @SerialName("QC_hash")
    @Required
    @Serializable(with = Base64URLStringSerializer::class)
    val documentHash: Base64URL,

    @SerialName("QC_hashAlgorithmOID")
    @Required
    val hashAlgorithm: HashAlgorithmOID,

) : TransactionData {
    init {
        require(TYPE == type) { "Expected 'type' to be '$TYPE'. Was: '$type'." }
        require(credentialIds.isNotEmpty()) { "'credential_ids' must not be empty." }
    }

    companion object {
        const val TYPE = "qcert_creation_acceptance"
    }
}
