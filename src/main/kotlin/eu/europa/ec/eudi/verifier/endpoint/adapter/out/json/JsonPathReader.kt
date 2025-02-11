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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.json

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import eu.europa.ec.eudi.prex.JsonPath
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/**
 * Utility class for reading values of [element] at given [JsonPaths][JsonPath].
 */
internal class JsonPathReader(val element: JsonElement) {

    private val objectMapper: ObjectMapper by lazy { jacksonObjectMapper() }
    private val json: String by lazy { Json.encodeToString(element) }

    /**
     * Reads the value at [path].
     */
    fun readPath(path: String): Result<JsonElement?> = runCatching {
        com.nfeld.jsonpathkt.JsonPath(path)
            .readFromJson<JsonNode>(json)
            ?.let { objectMapper.writeValueAsString(it) }
            ?.let { Json.parseToJsonElement(it) }
    }
}
