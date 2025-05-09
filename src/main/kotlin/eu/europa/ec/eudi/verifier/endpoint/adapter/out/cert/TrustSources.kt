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

data class TrustSources(
    private val x5CShouldBeMap: ConcurrentMap<Regex, X5CShouldBe> = ConcurrentMap(),
) {
    private val logger: Logger = LoggerFactory.getLogger(TrustSources::class.java)

    fun forType(type: String): Option<X5CShouldBe> {
        return x5CShouldBeMap.entries
            .firstOrNull { (pattern, _) -> pattern.matches(type) }
            ?.value
            .toOption()
    }

    fun updateWithX5CShouldBe(pattern: Regex, x5CShouldBe: X5CShouldBe) {
        x5CShouldBeMap[pattern] = x5CShouldBe

        logger.info("TrustSources updated for pattern $pattern with ${x5CShouldBe.caCertificates().size} certificates")
    }
}
