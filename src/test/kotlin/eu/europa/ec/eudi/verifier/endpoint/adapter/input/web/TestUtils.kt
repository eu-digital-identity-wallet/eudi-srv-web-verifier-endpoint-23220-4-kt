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

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.ParseJarmOptionNimbus
import eu.europa.ec.eudi.verifier.endpoint.domain.JarmOption
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.text.ParseException

object TestUtils {

    private val jsonFormat: Json = Json { prettyPrint = true }
    fun loadResource(f: String): String =
        TestUtils::class.java.classLoader.getResourceAsStream(f)
            .let { String(it!!.readBytes()) }

    /**
     * Pretty print json element
     */
    fun prettyPrintJson(msg: String? = null, e: JsonElement) {
        println("${msg.orEmpty()}${jsonFormat.encodeToString(e)}")
    }

    /**
     *  function to parse jwt token using nimbus
     */
    private fun parseJWT(accessToken: String): Pair<JWSHeader, JWTClaimsSet> {
        try {
            val decodedJWT = SignedJWT.parse(accessToken)
            return decodedJWT.header to decodedJWT.jwtClaimsSet
        } catch (e: ParseException) {
            throw Exception("Invalid token!")
        }
    }

    /**
     *  function to parse jwt token using nimbus
     */
    fun parseJWTIntoClaims(jwt: Jwt): Pair<JsonObject, JsonObject> {
        val (h, p) = parseJWT(jwt)
        return (h.claims() to p.claims()).also { (header, payload) ->
            prettyPrintJson("header\n", header)
            prettyPrintJson("payload\n", payload)
        }
    }

    private fun JWTClaimsSet.claims(): JsonObject = jsonFormat.parseToJsonElement(toString()).jsonObject
    private fun JWSHeader.claims(): JsonObject = jsonFormat.parseToJsonElement(toString()).jsonObject
}

fun JsonObject.ecKey(): ECKey? = fromClientMetaData { clientMetaData ->
    clientMetaData["jwks"]?.let { jwkSetJson ->
        JWKSet.parse(jwkSetJson.toString()).keys.firstOrNull { jwk -> jwk.keyType == KeyType.EC }
    }?.toECKey()
}

fun JsonObject.jarmOption(): JarmOption? = fromClientMetaData { clientMetaData ->
    val a = clientMetaData["authorization_signed_response_alg"]?.jsonPrimitive?.contentOrNull
    val b = clientMetaData["authorization_encrypted_response_alg"]?.jsonPrimitive?.contentOrNull
    val c = clientMetaData["authorization_encrypted_response_enc"]?.jsonPrimitive?.contentOrNull
    ParseJarmOptionNimbus(a, b, c)
}

fun <A> JsonObject.fromClientMetaData(extract: (JsonObject) -> A): A? {
    return this["client_metadata"]?.jsonObject?.let { extract(it) }
}
