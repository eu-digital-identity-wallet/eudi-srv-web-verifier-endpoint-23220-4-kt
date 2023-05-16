package eu.europa.ec.euidw.verifier.application.port.`in`

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
internal class StaticContentRouterTest () {

    @Autowired
    private lateinit var client: WebTestClient

    @Test
    fun `confirm StaticApi router is accessible, should return 200`() {
        client.get().uri("/index.html")
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult().responseBodyContent?.let { println("response: ${String(it)}") }
    }

}