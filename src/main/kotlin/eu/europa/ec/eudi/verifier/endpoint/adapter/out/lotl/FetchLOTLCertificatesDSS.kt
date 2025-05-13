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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.lotl

import eu.europa.ec.eudi.verifier.endpoint.domain.TrustSourceConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader
import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.cache.CacheCleaner
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.job.TLValidationJob
import eu.europa.esig.dss.tsl.source.LOTLSource
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.DisposableBean
import org.springframework.core.io.DefaultResourceLoader
import java.net.URL
import java.nio.file.Files
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.function.Predicate
import kotlin.time.measureTimedValue

private val logger: Logger = LoggerFactory.getLogger(FetchLOTLCertificatesDSS::class.java)

class FetchLOTLCertificatesDSS(
    private val executorService: ExecutorService = Executors.newFixedThreadPool(4),
) : FetchLOTLCertificates, DisposableBean {
    private val dispatcher = executorService.asCoroutineDispatcher()

    override fun destroy() {
        dispatcher.close()
    }

    override suspend fun invoke(
        url: URL,
        serviceTypeFilter: String?,
        keystoreConfig: TrustSourceConfig.KeyStoreConfig?,
    ): Result<List<X509Certificate>> = runCatching {
        val trustedListsCertificateSource = TrustedListsCertificateSource()

        val tlCacheDirectory = Files.createTempDirectory("lotl-cache").toFile()

        val offlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
            setCacheExpirationTime(24 * 60 * 60 * 1000)
            setFileCacheDirectory(tlCacheDirectory)
            dataLoader = IgnoreDataLoader()
        }

        val onlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
            setCacheExpirationTime(24 * 60 * 60 * 1000)
            setFileCacheDirectory(tlCacheDirectory)
            dataLoader = CommonsDataLoader()
        }

        val cacheCleaner = CacheCleaner().apply {
            setCleanMemory(true)
            setCleanFileSystem(true)
            setDSSFileLoader(offlineLoader)
        }

        val validationJob = TLValidationJob().apply {
            setListOfTrustedListSources(lotlSource(url, serviceTypeFilter, keystoreConfig))
            setOfflineDataLoader(offlineLoader)
            setOnlineDataLoader(onlineLoader)
            setTrustedListCertificateSource(trustedListsCertificateSource)
            setSynchronizationStrategy(ExpirationAndSignatureCheckStrategy())
            setCacheCleaner(cacheCleaner)
            setExecutorService(executorService)
        }

        logger.info("Starting validation job")
        val (certs, duration) = measureTimedValue {
            withContext(dispatcher) {
                validationJob.onlineRefresh()
            }

            trustedListsCertificateSource.certificates.map {
                it.certificate
            }
        }
        logger.info("Finished validation job in $duration")
        certs
    }

    private suspend fun lotlSource(
        url: URL,
        serviceTypeFilter: String?,
        keystoreConfig: TrustSourceConfig.KeyStoreConfig?,
    ): LOTLSource = LOTLSource().apply {
        this.url = url.toString()
        keystoreConfig
            ?.let { lotlCertificateSource(it).getOrNull() }
            ?.let { certificateSource = it }
        isPivotSupport = true
        trustAnchorValidityPredicate = GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate()
        tlVersions = listOf(5, 6)
        serviceTypeFilter?.let {
            trustServicePredicate = Predicate { tspServiceType ->
                tspServiceType.serviceInformation.serviceTypeIdentifier == it
            }
        }
    }

    private suspend fun lotlCertificateSource(keystoreConfig: TrustSourceConfig.KeyStoreConfig): Result<KeyStoreCertificateSource> =
        withContext(dispatcher + CoroutineName("LotlCertificateSource-${keystoreConfig.keystorePath}")) {
            runCatching {
                val resource = DefaultResourceLoader().getResource(keystoreConfig.keystorePath)
                KeyStoreCertificateSource(
                    resource.inputStream,
                    keystoreConfig.keystoreType,
                    keystoreConfig.keystorePassword,
                )
            }
        }
}
