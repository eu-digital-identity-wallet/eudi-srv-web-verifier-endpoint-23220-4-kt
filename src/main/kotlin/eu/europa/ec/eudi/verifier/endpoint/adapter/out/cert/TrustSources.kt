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

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Functional interface for providing appropriate X5CShouldBe trust source based on document type.
 */
fun interface ProvideTrustSource {
    /**
     * Returns the appropriate X5CShouldBe for the given doctype/vct.
     *
     * @param type The doctype/vct
     * @return The X5CShouldBe configuration for the doctype/vct
     */
    suspend operator fun invoke(type: String): X5CShouldBe?
}

class TrustSources : ProvideTrustSource {
    private val logger: Logger = LoggerFactory.getLogger(TrustSources::class.java)
    private val x5CShouldBeMap = mutableMapOf<Regex, X5CShouldBe>()
    private val mutex = Mutex()

    suspend fun updateWithX5CShouldBe(pattern: Regex, x5CShouldBe: X5CShouldBe) {
        mutex.withLock {
            x5CShouldBeMap[pattern] = x5CShouldBe
            logger.info("TrustSources updated for pattern $pattern with ${x5CShouldBe.caCertificates().size} certificates")
        }
    }

    /**
     * Implementation of TrustSourceProvider
     * Retrieves the X5CShouldBe for the given document type.
     */
    override suspend fun invoke(type: String): X5CShouldBe? =
        mutex.withLock {
            x5CShouldBeMap.entries
                .firstOrNull { (pattern, _) -> pattern.matches(type) }
                ?.value
        }
}
