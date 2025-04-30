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

import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.TrustSources
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustSourceConfig
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.SchedulingConfigurer
import org.springframework.scheduling.config.CronTask
import org.springframework.scheduling.config.ScheduledTaskRegistrar
import java.security.cert.X509Certificate

@EnableScheduling
class RefreshTrustSources(
    private val fetchLOTLCertificates: FetchLOTLCertificates,
    private var trustSources: TrustSources,
    private val verifierConfig: VerifierConfig,
) : SchedulingConfigurer {

    private val logger: Logger = LoggerFactory.getLogger(RefreshTrustSources::class.java)

    fun initializeTrustSources() {
        verifierConfig.trustSourcesConfig.forEach { (regex, trustSourceConfig) ->
            val keystoreCertificates = trustSourceConfig.keystore.loadCertificates(regex)

            trustSourceConfig.trustedList?.let {
                runBlocking(Dispatchers.IO) {
                    it.loadCertificates(regex, keystoreCertificates)
                }
            }
        }
    }

    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        // Configure LOTL refresh tasks for each trust source that has LOTL configuration
        verifierConfig.trustSourcesConfig.forEach { (regex, trustSourceConfig) ->
            trustSourceConfig.trustedList?.let {
                val keystoreCertificates = trustSourceConfig.keystore.loadCertificates(regex)
                taskRegistrar.addCronTask(
                    CronTask({
                        runBlocking(Dispatchers.IO) {
                            it.loadCertificates(regex, keystoreCertificates)
                        }
                    }, it.refreshInterval),
                )
            }
        }
    }

    private suspend fun TrustSourceConfig.TrustedList.loadCertificates(
        expression: Regex,
        keystoreCertificates: List<X509Certificate>?,
    ) = fetchLOTLCertificates(location, serviceTypeFilter)
        .onFailure {
            logger.error("Failed to fetch LOTL certificates from $location", it)
        }.onSuccess {
            trustSources.updateWithCertificates(expression, it + keystoreCertificates.orEmpty())
        }

    private fun TrustSourceConfig.Keystore?.loadCertificates(regex: Regex) = this?.let {
        val x5CShouldBe = X5CShouldBe.fromKeystore(it.value)
        trustSources.updateWithX5CShouldBe(regex, x5CShouldBe)
        x5CShouldBe.caCertificates()
    }
}
