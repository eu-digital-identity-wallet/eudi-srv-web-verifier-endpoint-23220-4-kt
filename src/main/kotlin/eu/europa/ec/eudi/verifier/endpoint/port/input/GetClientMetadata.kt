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

import eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata.toJsonObject
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject

/**
 * Gets the Client Metadata of the Verifier Endpoint encoded as a JsonObject.
 */
fun interface GetClientMetadata {
    operator fun invoke(): JsonObject
}

internal class GetClientMetadataLive(
    private val verifierConfig: VerifierConfig,
) : GetClientMetadata {

    override fun invoke(): JsonObject =
        with(verifierConfig.clientMetaData) {
            buildJsonObject {
                put("vp_formats", vpFormats.toJsonObject())
            }
        }
}
