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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc

import eu.europa.ec.eudi.sdjwt.vc.KtorHttpClientFactory
import eu.europa.ec.eudi.sdjwt.vc.LookupTypeMetadata
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcTypeMetadata
import eu.europa.ec.eudi.sdjwt.vc.Vct
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.http.*

class LookupTypeMetadataFromPidIssuer(
    private val httpClient: KtorHttpClientFactory,
    private val serviceUrl: Url,
) : LookupTypeMetadata {
    override suspend fun invoke(vct: Vct): Result<SdJwtVcTypeMetadata?> = runCatching {
        val response = httpClient().request(serviceUrl) {
            url {
                expectSuccess = false
                appendPathSegments("type-metadata", vct.value)
            }
            method = HttpMethod.Get
        }
        when (response.status) {
            HttpStatusCode.OK -> response.body<SdJwtVcTypeMetadata>()
            HttpStatusCode.NotFound -> null
            else -> throw ResponseException(response, "Failed to retrieve type metadata")
        }
    }
}
