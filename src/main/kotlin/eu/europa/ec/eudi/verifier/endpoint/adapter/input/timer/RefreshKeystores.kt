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
import jakarta.annotation.PostConstruct
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.SchedulingConfigurer
import org.springframework.scheduling.config.CronTask
import org.springframework.scheduling.config.ScheduledTaskRegistrar
import org.springframework.stereotype.Component
import java.security.cert.X509Certificate

@EnableScheduling
@Component
class RefreshKeystores(
    private val fetchLOTLCertificates: FetchLOTLCertificates,
    private var trustSources: TrustSources,
    private val verifierConfig: VerifierConfig,
) : SchedulingConfigurer {

    private val logger: Logger = LoggerFactory.getLogger(RefreshKeystores::class.java)

    @PostConstruct // TODO GD: remove annotation and initialize in verifier context
    fun initializeTrustSources() {
        verifierConfig.trustSourcesConfig.forEach { trustSource ->
            trustSource.value.keystore?.let { loadCertificatesFromKeystore(trustSource.key, it) }
        }
    }

    private fun loadCertificatesFromKeystore(regex: Regex, keystoreConfig: TrustSourceConfig.Keystore): List<X509Certificate> {
        val x5CShouldBe = keystoreConfig.value.let {
            X5CShouldBe.fromKeystore(it)
        }
        trustSources.updateWithX5CShouldBe(regex, x5CShouldBe)
        return x5CShouldBe.caCertificates()
    }

    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        // Configure LOTL refresh tasks for each trust source that has LOTL configuration
        verifierConfig.trustSourcesConfig.forEach { trustSource ->
            val regex = trustSource.key
            val trustSourceConfig = trustSource.value

            val keystoreCertificates = trustSourceConfig.keystore?.let {
                loadCertificatesFromKeystore(regex, it)
            } ?: emptyList()

            trustSourceConfig.trustedList?.let {
                taskRegistrar.addCronTask(
                    CronTask({
                        runBlocking(Dispatchers.IO) {
                            val lotlUrl = it.location
                            // TODO GD: use map
                            fetchLOTLCertificates(lotlUrl, it.serviceTypeFilter).also { result ->
                                if (result.isFailure) {
                                    logger.error(
                                        "Failed to fetch LOTL certificates from $lotlUrl",
                                        result.exceptionOrNull(),
                                    )
                                } else {
                                    val lotlCertificates = result.getOrNull() ?: emptyList()
                                    logger.info("Fetched ${lotlCertificates.size} LOTL certificates from $lotlUrl")

                                    // Update the trust sources with the fetched certificates
                                    trustSources.updateWithCertificates(regex, lotlCertificates + keystoreCertificates)
                                }
                            }
                        }
                    }, it.refreshInterval),
                )
            }
        }
    }
}
