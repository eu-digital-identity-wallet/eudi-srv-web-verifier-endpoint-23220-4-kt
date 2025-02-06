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

import cbor.Cbor
import id.walt.mdoc.dataelement.EncodedCBORElement
import id.walt.mdoc.dataretrieval.DeviceResponse
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mso.MSO
import kotlinx.serialization.decodeFromByteArray
import kotlin.io.encoding.Base64

private val cbor: Cbor by lazy {
    Cbor {
        ignoreUnknownKeys = true
    }
}

private val base64UrlNoPadding: Base64 by lazy {
    Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
}

/**
 * Decodes a [DeviceResponse] from a Base64 URL encoded CBOR value.
 *
 * Unknown properties are ignored.
 */
fun DeviceResponse.Companion.decodeFromCborBase64Url(value: String): DeviceResponse {
    val decoded = base64UrlNoPadding.decode(value)
    return cbor.decodeFromByteArray(decoded)
}

/**
 * Decodes the [MSO] of this [MDoc].
 *
 * Unknown properties are ignored.
 *
 * **This is a hack to circumvent a `walt.id` library limitation. Currently, it does not support the `status` property in [MSO].**
 */
fun MDoc.decodeMso() {
    if (_mso == null) {
        _mso = issuerSigned.issuerAuth?.payload?.let { data ->
            val encoded = cbor.decodeFromByteArray<EncodedCBORElement>(data)
            cbor.decodeFromByteArray<MSO>(encoded.value)
        }
    }
}
