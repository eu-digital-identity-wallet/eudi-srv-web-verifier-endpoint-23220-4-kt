package eu.europa.ec.euidw.verifier

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Import

@Import(VerifierContext::class)
@SpringBootApplication(proxyBeanMethods = false)
class VerifierApplication

fun main(args: Array<String>) {
    runApplication<VerifierApplication>(*args)
}
