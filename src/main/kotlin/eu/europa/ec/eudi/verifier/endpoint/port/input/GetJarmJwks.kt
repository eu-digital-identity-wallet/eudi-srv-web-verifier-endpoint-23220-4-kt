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

import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.jwk
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId

/**
 * Given a [RequestId] returns the [JWKSet] to be used for JARM.
 */
fun interface GetJarmJwks {
    suspend operator fun invoke(id: RequestId): QueryResponse<JWKSet>
}

internal class GetJarmJwksLive(private val loadPresentationByRequestId: LoadPresentationByRequestId) : GetJarmJwks {

    override suspend fun invoke(id: RequestId): QueryResponse<JWKSet> =
        when (val presentation = loadPresentationByRequestId(id)) {
            null -> QueryResponse.NotFound
            is Presentation.RequestObjectRetrieved -> {
                if (presentation.ephemeralEcPrivateKey != null) {
                    QueryResponse.Found(JWKSet(listOf(presentation.ephemeralEcPrivateKey.jwk())).toPublicJWKSet())
                } else {
                    QueryResponse.InvalidState
                }
            }

            else -> QueryResponse.InvalidState
        }
}
