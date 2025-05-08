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

import io.ktor.util.collections.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Functional interface for providing appropriate X5CShouldBe trust source based on document type.
 */
fun interface TrustSourceProvider {
    /**
     * Returns the appropriate X5CShouldBe for the given doctype/vct.
     *
     * @param type The doctype/vct
     * @return The X5CShouldBe configuration for the doctype/vct
     */
    fun invoke(type: String): X5CShouldBe?
}

data class TrustSources(
    private val x5CShouldBeMap: ConcurrentMap<Regex, X5CShouldBe> = ConcurrentMap(),
) : TrustSourceProvider {
    private val logger: Logger = LoggerFactory.getLogger(TrustSources::class.java)

    fun updateWithX5CShouldBe(pattern: Regex, x5CShouldBe: X5CShouldBe) {
        x5CShouldBeMap[pattern] = x5CShouldBe

        logger.info("TrustSources updated for pattern $pattern with ${x5CShouldBe.caCertificates().size} certificates")
    }

    /**
     * Implementation of TrustSourceProvider.invoke
     * Retrieves the X5CShouldBe for the given document type.
     */
    override fun invoke(type: String): X5CShouldBe? {
        return x5CShouldBeMap.entries
            .firstOrNull { (pattern, _) -> pattern.matches(type) }
            ?.value
    }
}
