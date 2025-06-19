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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import arrow.core.Either
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationExchange

/**
 * Nimbus library depends on Jackson for JSON parsing
 * On the other hand, [PresentationDefinition] depends on [PresentationExchange.jsonParser]
 * which is based on the Kotlinx Serialization library.
 *
 * This class offers two util methods for [mapping][PresentationDefinitionJackson.toJsonObject]
 * a [PresentationDefinition] to a jackson compatible object
 * and [vice versa][PresentationDefinitionJackson.fromJsonObject]
 */
object PresentationDefinitionJackson {

    private val objectMapper: ObjectMapper by lazy { ObjectMapper() }

    fun toJsonObject(pd: PresentationDefinition): Any {
        val jsonStr = with(PresentationExchange.jsonParser) { pd.encode() }
        return objectMapper.readValue<Any>(jsonStr)
    }

    fun fromJsonObject(o: Map<String, Any?>): Either<Throwable, PresentationDefinition> = Either.catch {
        val jsonStr = objectMapper.writeValueAsString(o)
        PresentationExchange.jsonParser.decodePresentationDefinition(jsonStr).getOrThrow()
    }
}
