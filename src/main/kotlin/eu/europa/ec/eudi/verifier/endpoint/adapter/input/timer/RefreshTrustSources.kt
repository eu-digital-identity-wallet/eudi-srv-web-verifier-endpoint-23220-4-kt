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

@EnableScheduling
class RefreshTrustSources(
    private val fetchLOTLCertificates: FetchLOTLCertificates,
    private var trustSources: TrustSources,
    private val verifierConfig: VerifierConfig,
) : SchedulingConfigurer {

    private val logger: Logger = LoggerFactory.getLogger(RefreshTrustSources::class.java)

    fun initializeTrustSources() {
        verifierConfig.trustSourcesConfig.forEach { (regex, trustSourceConfig) ->
            val keystoreCertificates = trustSourceConfig.keystore.loadCertificates()
            val lotlCertificates = trustSourceConfig.trustedList?.let {
                runBlocking(Dispatchers.IO) {
                    it.loadCertificates()
                }.getOrNull()
            }
            trustSources.updateWithCertificates(
                regex,
                lotlCertificates.orEmpty() + keystoreCertificates.orEmpty(),
            )
        }
    }

    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        // Configure LOTL refresh tasks for each trust source that has LOTL configuration
        verifierConfig.trustSourcesConfig.forEach { (regex, trustSourceConfig) ->
            trustSourceConfig.trustedList?.let {
                taskRegistrar.addCronTask(
                    CronTask({
                        val keystoreCertificates = trustSourceConfig.keystore.loadCertificates()
                        val lotlCertificates = runBlocking(Dispatchers.IO) {
                            it.loadCertificates()
                        }.getOrNull()
                        trustSources.updateWithCertificates(
                            regex,
                            lotlCertificates.orEmpty() + keystoreCertificates.orEmpty(),
                        )
                    }, it.refreshInterval),
                )
            }
        }
    }

    private suspend fun TrustSourceConfig.TrustedListConfig.loadCertificates() = fetchLOTLCertificates(
        location,
        serviceTypeFilter,
        keystoreConfig,
    )
        .onFailure {
            logger.error("Failed to fetch LOTL certificates from $location", it)
        }

    private fun TrustSourceConfig.KeyStoreConfig?.loadCertificates() = this?.let {
        val x5CShouldBe = X5CShouldBe.fromKeystore(it.keystore)
        x5CShouldBe.caCertificates()
    }
}
