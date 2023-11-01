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
package eu.europa.ec.eudi.verifier.endpoint

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource

@Configuration
@EnableWebFluxSecurity
class VerifierSecurityConfiguration {

    @Value("\${cors.originPatterns:default}")
    private val corsOriginPatterns: String = ""

    @Value("\${cors.origins:default}")
    private val corsOrigins: String = ""

    @Value("\${cors.methods:GET,POST,PUT,DELETE,OPTIONS,PATCH}")
    private val corsMethods: String = ""

    @Value("\${cors.headers:*}")
    private val corsHeaders: String = ""

    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            cors { // cross-origin resource sharing configuration
                configurationSource = CorsConfigurationSource {
                    val corsConfiguration = CorsConfiguration()
                    corsConfiguration.allowedOriginPatterns = corsOriginPatterns.split(",").toList()
                    corsConfiguration.allowedOrigins = corsOrigins.split(",").toList()
                    corsConfiguration.allowedMethods = corsMethods.split(",").toList()
                    corsConfiguration.allowedHeaders = corsHeaders.split(",").toList()
                    corsConfiguration.allowCredentials = true
                    corsConfiguration.maxAge = 3600L
                    corsConfiguration
                }
            }
            csrf { disable() } // cross-site request forgery disabled
        }
    }
}
