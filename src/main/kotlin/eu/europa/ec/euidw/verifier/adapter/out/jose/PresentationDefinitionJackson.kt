package eu.europa.ec.euidw.verifier.adapter.out.jose

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationExchange

/**
 * Nimbus library depends on Jackson for JSON parsing
 * On the other hand, [PresentationDefinition] depends on [PresentationExchange.jsonParser]
 * which is based on Kotlinx Serialization library.
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

    fun fromJsonObject(o: MutableMap<String, Any?>): Result<PresentationDefinition> = runCatching {
        val jsonStr = objectMapper.writeValueAsString(o)
        PresentationExchange.jsonParser.decodePresentationDefinition(jsonStr).getOrThrow()
    }

}