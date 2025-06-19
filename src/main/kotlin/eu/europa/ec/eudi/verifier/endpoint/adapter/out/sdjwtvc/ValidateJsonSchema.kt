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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc

import com.networknt.schema.InputFormat
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SchemaValidatorsConfig
import com.networknt.schema.SpecVersion
import com.networknt.schema.regex.JoniRegularExpressionFactory
import eu.europa.ec.eudi.sdjwt.vc.JsonSchema
import eu.europa.ec.eudi.sdjwt.vc.JsonSchemaValidator
import eu.europa.ec.eudi.sdjwt.vc.JsonSchemaViolation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import com.networknt.schema.JsonSchema as ExternalJsonSchema

object ValidateJsonSchema : JsonSchemaValidator {
    override suspend fun validate(
        unvalidated: JsonObject,
        schema: JsonSchema,
    ): List<JsonSchemaViolation> {
        return JsonSchemaConverter.convert(schema = schema).validate(unvalidated)
    }
}
private object JsonSchemaConverter {
    private val config: SchemaValidatorsConfig by lazy {
        SchemaValidatorsConfig.Builder()
            .regularExpressionFactory(JoniRegularExpressionFactory.getInstance())
            .formatAssertionsEnabled(true)
            .build()
    }
    private val factory: JsonSchemaFactory by lazy {
        JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012) { factoryBuilder ->
            factoryBuilder.schemaLoaders { schemaLoadersBuilder ->
                schemaLoadersBuilder.add {
                    error("SchemaLoader should not have been invoked. Schema URI: $it")
                }
            }
            factoryBuilder.enableSchemaCache(true)
        }
    }

    suspend fun convert(schema: JsonSchema): ExternalJsonSchema =
        withContext(Dispatchers.IO) {
            val externalJsonSchema = factory.getSchema(Json.encodeToString(schema), InputFormat.JSON, config)
            check(SpecVersion.VersionFlag.V202012.id == externalJsonSchema.getRefSchemaNode("/\$schema").textValue())
            externalJsonSchema
        }
}

private fun ExternalJsonSchema.validate(unvalidated: JsonObject): List<JsonSchemaViolation> =
    validate(Json.encodeToString(unvalidated), InputFormat.JSON) { context ->
        context.executionConfig.formatAssertionsEnabled = true
    }.mapNotNull { JsonSchemaViolation(it.toString()) }
