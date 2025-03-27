package eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer

import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.SchedulingConfigurer
import org.springframework.scheduling.config.ScheduledTaskRegistrar
import java.net.URI
import kotlin.time.Duration.Companion.minutes

@EnableScheduling
class RefreshKeystores(private val fetchLOTLCertificates: FetchLOTLCertificates) : SchedulingConfigurer {

    private val logger: Logger = LoggerFactory.getLogger(ScheduleTimeoutPresentations::class.java)

    private val europeanLOTLUrl = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        taskRegistrar.addFixedRateTask(2.minutes) {
            runBlocking(Dispatchers.IO) {
                fetchLOTLCertificates(URI(europeanLOTLUrl).toURL()).also {
                    if (it.isFailure) {
                        logger.error("Failed to fetch LOTL certificates", it.exceptionOrNull())
                    } else {
                        logger.info("Fetched ${it.getOrNull()?.size} LOTL certificates")
                    }
                }
            }
        }
    }
}
