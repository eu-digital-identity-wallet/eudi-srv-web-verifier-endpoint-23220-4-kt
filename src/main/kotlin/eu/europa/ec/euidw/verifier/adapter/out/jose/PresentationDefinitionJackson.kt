package eu.europa.ec.euidw.verifier.adapter.out.jose

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.prex.PresentationExchange

object PresentationDefinitionJackson {

    private val objectMapper : ObjectMapper by lazy { ObjectMapper() }

    fun toJsonObject(pd: PresentationDefinition): Any {
        val jsonStr = with(PresentationExchange.jsonParser){pd.encode()}
        return objectMapper.readValue<Any>(jsonStr)
    }

    fun fromJsonObject(o: MutableMap<String, Any?>): Result<PresentationDefinition>  = runCatching{
        val jsonStr = objectMapper.writeValueAsString(o)
        PresentationExchange.jsonParser.decodePresentationDefinition(jsonStr).getOrThrow()
    }

}