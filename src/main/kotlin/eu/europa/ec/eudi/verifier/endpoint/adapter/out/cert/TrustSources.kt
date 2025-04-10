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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert

import java.security.cert.X509Certificate

data class TrustSources(
    val x5CShouldBeMap: MutableMap<Regex, X5CShouldBe> = mutableMapOf(),
) {
    /**
     * Updates trust sources for a specific pattern with the given certificates
     */
    fun updateWithCertificates(pattern: Regex, certificates: List<X509Certificate>) {
        val existing = x5CShouldBeMap[pattern]

        val updatedX5ShouldBe = if (existing is X5CShouldBe.Trusted) {
            X5CShouldBe(certificates, existing.customizePKIX)
        } else {
            X5CShouldBe.Ignored
        }

        x5CShouldBeMap[pattern] = updatedX5ShouldBe
    }

    fun updateWithX5CShouldBe(
        pattern: Regex,
        x5CShouldBe: X5CShouldBe,
    ) {
        x5CShouldBeMap[pattern] = x5CShouldBe
    }
}
