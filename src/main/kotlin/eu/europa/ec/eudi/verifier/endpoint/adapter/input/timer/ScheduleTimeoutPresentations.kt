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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer

import eu.europa.ec.eudi.verifier.endpoint.port.input.TimeoutPresentations
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled

class ScheduleTimeoutPresentations(private val timeoutPresentations: TimeoutPresentations) {

    private val logger: Logger = LoggerFactory.getLogger(ScheduleTimeoutPresentations::class.java)

    @Scheduled(fixedRate = 2000)
    fun timeout() {
        runBlocking(Dispatchers.IO) {
            timeoutPresentations().also {
                if (it.isNotEmpty()) logger.info("Timed out ${it.size} presentations")
            }
        }
    }
}
