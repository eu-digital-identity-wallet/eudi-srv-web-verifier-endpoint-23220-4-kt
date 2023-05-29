package eu.europa.ec.eudi.verifier.endpoint.adapter.`in`.web

import org.springframework.core.io.ClassPathResource
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.coRouter

class StaticContent() {

    val route = coRouter {
        accept(MediaType.TEXT_HTML).nest {
            resources("/**", ClassPathResource("/static/"))
        }
    }

}