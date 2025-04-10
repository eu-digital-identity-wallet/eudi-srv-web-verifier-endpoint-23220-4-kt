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
package eu.europa.ec.eudi.verifier.endpoint.port.out.lotl

import java.net.URL
import java.security.cert.X509Certificate

/**
 * Interface for fetching LOTL certificates
 */
interface FetchLOTLCertificates {
    /**
     * Fetch certificates from a LOTL URL
     * @param url The LOTL URL
     * @param serviceTypeFilter Optional filter for service types
     * @return Result containing a list of X509 certificates or an exception
     */
    suspend operator fun invoke(url: URL, serviceTypeFilter: String? = null): Result<List<X509Certificate>>
}
