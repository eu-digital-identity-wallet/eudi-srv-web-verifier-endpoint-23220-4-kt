package eu.europa.ec.eudi.verifier.endpoint

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication(proxyBeanMethods = false)
class VerifierApplication

fun main(args: Array<String>) {
    runApplication<VerifierApplication>(*args)
}
