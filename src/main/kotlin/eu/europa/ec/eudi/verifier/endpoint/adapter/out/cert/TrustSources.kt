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

import arrow.core.Option
import arrow.core.toOption
import io.ktor.util.collections.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate

data class TrustSources(
    private val x5CShouldBeMap: ConcurrentMap<Regex, X5CShouldBe> = ConcurrentMap(),
) {
    private val logger: Logger = LoggerFactory.getLogger(TrustSources::class.java)

    fun forType(docType: String): Option<X5CShouldBe> {
        return x5CShouldBeMap.entries
            .firstOrNull { (pattern, _) -> pattern.matches(docType) }
            ?.value
            .toOption()
    }

    /**
     * Updates trust sources for a specific pattern with the given certificates
     */
    fun updateWithCertificates(pattern: Regex, certificates: List<X509Certificate>) {
        x5CShouldBeMap[pattern] = when (val existing = x5CShouldBeMap[pattern]) {
            is X5CShouldBe.Trusted -> X5CShouldBe(certificates, existing.customizePKIX)
            else -> X5CShouldBe.Ignored
        }

        logger.info("TrustSources updated for pattern $pattern with ${certificates.size} certificates")
    }

    fun updateWithX5CShouldBe(pattern: Regex, x5CShouldBe: X5CShouldBe) {
        x5CShouldBeMap[pattern] = x5CShouldBe

        logger.info("TrustSources updated for pattern $pattern with ${x5CShouldBe.caCertificates().size} certificates")
    }
}
