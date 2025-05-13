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
import org.springframework.beans.factory.InitializingBean
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
) : InitializingBean, SchedulingConfigurer {
    private val ioDispatcher = Dispatchers.IO.limitedParallelism(2)

    override fun afterPropertiesSet() {
        runBlocking { updateLOTLs() }
    }

    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        // Configure LOTL refresh tasks for each trust source that has LOTL configuration
        verifierConfig.trustSourcesConfig.forEach { (regex, trustSourceConfig) ->
            trustSourceConfig.trustedList?.let {
                taskRegistrar.addCronTask(
                    CronTask(
                        {
                            CoroutineScope(ioDispatcher + CoroutineName("$regex")).launch {
                                val certs = trustSourceConfig.fetchCerts()
                                trustSources.updateWithX5CShouldBe(regex, certs)
                            }
                        },
                        it.refreshInterval,
                    ),
                )
            }
        }
    }

    private suspend fun updateLOTLs() =
        withContext(ioDispatcher + CoroutineName("initializing LOTL(s)")) {
            verifierConfig.trustSourcesConfig.map { (regex, trustSourceConfig) ->
                launch { trustSources.updateWithX5CShouldBe(regex, trustSourceConfig.fetchCerts()) }
            }.joinAll()
        }

    private suspend fun TrustSourcesConfig.fetchCerts(): List<X509Certificate> =
        coroutineScope {
            suspend fun TrustSourceConfig.TrustedListConfig.lotlCerts(): List<X509Certificate> =
                fetchLOTLCertificates(location, serviceTypeFilter, keystoreConfig).getOrThrow()

            suspend fun TrustSourceConfig.KeyStoreConfig.keyCerts(): List<X509Certificate> =
                withContext(ioDispatcher) {
                    val x5CShouldBe = X5CShouldBe.fromKeystore(keystore)
                    x5CShouldBe.caCertificates()
                }

            val keystoreCertificates = async { keystore?.keyCerts().orEmpty() }
            val lotlCertificates = async { trustedList?.lotlCerts().orEmpty() }
            lotlCertificates.await() + keystoreCertificates.await()
        }
}
