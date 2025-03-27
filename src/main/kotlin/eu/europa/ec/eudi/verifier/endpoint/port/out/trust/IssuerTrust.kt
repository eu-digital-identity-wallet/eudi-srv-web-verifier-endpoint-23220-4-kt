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
package eu.europa.ec.eudi.verifier.endpoint.port.out.trust

import eu.europa.ec.eudi.sdjwt.vc.Vct
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.domain.MsoMdocDocType

/**
 * Service for querying for Trusted Issuers of Verifiable Credentials
 */
interface IssuerTrust {

    /**
     * Gets the Trusted Issuers of SD-JWT VCs with the provided [vct].
     */
    suspend fun getTrustedIssuers(vct: Vct): X5CShouldBe

    /**
     * Gets the Trusted Issuers of MSO MDoc VCs with the provided [docType].
     */
    suspend fun getTrustedIssuers(docType: MsoMdocDocType): X5CShouldBe
}
