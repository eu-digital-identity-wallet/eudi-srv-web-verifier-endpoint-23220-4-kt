package eu.europa.ec.euidw.verifier.adapter.`in`.timer

import eu.europa.ec.euidw.verifier.application.port.`in`.TimeoutPresentations
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.apache.commons.logging.Log
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled

class ScheduleTimeoutPresentations(private val timeoutPresentations: TimeoutPresentations) {

    private val logger :Logger = LoggerFactory.getLogger(ScheduleTimeoutPresentations::class.java)

    @Scheduled(fixedRate = 2000)
    fun timeout() {
        runBlocking(Dispatchers.IO) {

            timeoutPresentations().also {
                if (it.isNotEmpty()) logger.info("Timed out ${it.size} presentations")
            }
        }
    }
}