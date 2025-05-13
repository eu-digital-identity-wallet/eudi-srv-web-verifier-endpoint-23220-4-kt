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
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustSourcesConfig
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import kotlinx.coroutines.*
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

    val coroutineScope = CoroutineScope(Dispatchers.IO.limitedParallelism(3))

    fun initializeTrustSources() {
        coroutineScope.launch {
            verifierConfig.trustSourcesConfig.forEach { (regex, trustSourceConfig) ->
                trustSourceConfig.refreshTrustSources(regex)
            }
        }
    }

    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        // Configure LOTL refresh tasks for each trust source that has LOTL configuration
        verifierConfig.trustSourcesConfig.forEach { (regex, trustSourceConfig) ->
            trustSourceConfig.trustedList?.let {
                taskRegistrar.addCronTask(
                    CronTask(
                        {
                            coroutineScope.launch {
                                trustSourceConfig.refreshTrustSources(regex)
                            }
                        },
                        it.refreshInterval,
                    ),
                )
            }
        }
    }

    private suspend fun TrustSourcesConfig.refreshTrustSources(regex: Regex) =
        coroutineScope {
            suspend fun TrustSourceConfig.TrustedListConfig.lotlCerts(): List<X509Certificate> =
                fetchLOTLCertificates(location, serviceTypeFilter, keystoreConfig).getOrThrow()

            fun TrustSourceConfig.KeyStoreConfig.keyCerts(): List<X509Certificate> {
                val x5CShouldBe = X5CShouldBe.fromKeystore(keystore)
                return x5CShouldBe.caCertificates()
            }

            val keystoreCertificates = async { keystore?.keyCerts().orEmpty() }
            val lotlCertificates = async { trustedList?.lotlCerts().orEmpty() }

            trustSources.updateWithX5CShouldBe(
                regex,
                X5CShouldBe(
                    rootCACertificates = lotlCertificates.await() + keystoreCertificates.await(),
                    customizePKIX = { isRevocationEnabled = false },
                ),
            )
        }
}
