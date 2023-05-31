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

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonMapperBuilder
import com.nimbusds.jwt.SignedJWT
import java.text.ParseException

object TestUtils {

    fun loadResource(f: String): String =
        TestUtils::class.java.classLoader.getResourceAsStream(f)
            .let { String(it!!.readBytes()) }

    /**
     * Pretty print json string
     */
    fun prettyPrintJson(jsonString: String?): String {
        val mapper = jacksonMapperBuilder().build()
        mapper.enable(SerializationFeature.INDENT_OUTPUT)
        val json = when (jsonString) {
            null, "" -> mapper.readValue("{}", Any::class.java)
            else -> mapper.readValue(jsonString, Any::class.java)
        }
        return mapper.writeValueAsString(json)
    }

    /**
     * Compare two json strings
     */
    fun compareJsonStrings(jsonString1: String, jsonString2: String): Boolean {
        val mapper = ObjectMapper()
        val jsonNode1 = mapper.readTree(jsonString1)
        val jsonNode2 = mapper.readTree(jsonString2)
        return jsonNode1.equals(jsonNode2)
    }

    /**
     *  function to parse jwt token using nimbus
     */
    fun parseJWT(accessToken: String): Pair<String, String> {
        try {
            val decodedJWT = SignedJWT.parse(accessToken)
            val header = decodedJWT.header.toString()
            val payload = decodedJWT.payload.toString()
            return Pair(header, payload)
        } catch (e: ParseException) {
            throw Exception("Invalid token!")
        }
    }
}
