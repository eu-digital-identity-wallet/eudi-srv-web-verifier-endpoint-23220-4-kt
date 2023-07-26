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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import org.junit.jupiter.api.Test
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
internal class StaticContentRouterTest() {
    private val log: Logger = LoggerFactory.getLogger(StaticContentRouterTest::class.java)

    @Autowired
    private lateinit var client: WebTestClient

    @Test
    fun `confirm StaticApi router is accessible, should return 200`() {
        client.get().uri("/index.html")
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult().responseBodyContent?.let { log.info("response: ${String(it)}") }
    }
}
