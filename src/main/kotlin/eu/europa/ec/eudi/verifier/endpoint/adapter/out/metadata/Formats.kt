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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.domain.OpenId4VPSpec
import eu.europa.ec.eudi.verifier.endpoint.domain.VpFormat.CoseAlgorithm
import eu.europa.ec.eudi.verifier.endpoint.domain.VpFormatsSupported
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement

internal object JWSAlgorithmStringSerializer : KSerializer<JWSAlgorithm> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("JWSAlgorithmString", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: JWSAlgorithm) {
        encoder.encodeString(value.name)
    }
    override fun deserialize(decoder: Decoder): JWSAlgorithm = JWSAlgorithm.parse(decoder.decodeString())
}

internal object COSEAlgorithmStringSerializer : KSerializer<CoseAlgorithm> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("CoseAlgorithmString", PrimitiveKind.INT)
    override fun serialize(encoder: Encoder, value: CoseAlgorithm) {
        encoder.encodeInt(value.algorithm)
    }

    override fun deserialize(decoder: Decoder): CoseAlgorithm = CoseAlgorithm(decoder.decodeInt())
}

@Serializable
internal data class SdJwtVcFormatTO(
    @Required
    @SerialName("sd-jwt_alg_values")
    val sdJwtAlgorithms: List<
        @Serializable(with = JWSAlgorithmStringSerializer::class)
        JWSAlgorithm,
        >,

    @Required
    @SerialName("kb-jwt_alg_values")
    val kbJwtAlgorithms: List<
        @Serializable(with = JWSAlgorithmStringSerializer::class)
        JWSAlgorithm,
        >,
) {
    init {
        require(sdJwtAlgorithms.isNotEmpty())
        require(kbJwtAlgorithms.isNotEmpty())
    }
}

@Serializable
internal data class MsoMdocFormatTO(
    @Required
    @SerialName(OpenId4VPSpec.ISSUER_AUTH_ALG_VALUES)
    val issuerAuthAlgorithms: List<
        @Serializable(with = COSEAlgorithmStringSerializer::class)
        CoseAlgorithm,
        >,
    @Required
    @SerialName(OpenId4VPSpec.DEVICE_AUTH_ALG_VALUES)
    val deviceAuthAlgorithms: List<
        @Serializable(with = COSEAlgorithmStringSerializer::class)
        CoseAlgorithm,
        >,
) {
    init {
        require(issuerAuthAlgorithms.isNotEmpty() && deviceAuthAlgorithms.isNotEmpty())
    }
}

/**
 * Converts this collection of VpFormats to a JsonObject that can be embedded in OIDCClientMetadata.
 */
internal fun VpFormatsSupported.toJsonObject(): JsonObject = buildJsonObject {
    val sdJwtVcFormatTO = jsonSupport.encodeToJsonElement(SdJwtVcFormatTO(sdJwtVc.sdJwtAlgorithms, sdJwtVc.kbJwtAlgorithms))
    put(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT, sdJwtVcFormatTO)

    val msoMdocFormatTO = jsonSupport.encodeToJsonElement(
        MsoMdocFormatTO(
            issuerAuthAlgorithms = msoMdoc.issuerAuthAlg,
            deviceAuthAlgorithms = msoMdoc.deviceAuthAlg,
        ),
    )
    put(OpenId4VPSpec.FORMAT_MSO_MDOC, msoMdocFormatTO)
}
