package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.redis

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer
import org.springframework.data.redis.serializer.RedisSerializer

@Serializable
data class SerializationWrapper(
    val type: String,
    val data: String
)

class KotlinJsonRedisSerializer : RedisSerializer<Any> {

    private val json = Json {
        serializersModule = SerializersModule {
            // Register polymorphic serializers if needed
        }
        ignoreUnknownKeys = true
        isLenient = true
    }

    override fun serialize(value: Any?): ByteArray? {
        if (value == null) return null
        val serializer = json.serializersModule.serializer(value.javaClass)
        val jsonString = json.encodeToString(serializer, value)
        val wrapper = SerializationWrapper(
            type = value.javaClass.name ?: error("Class name not found"),
            data = jsonString
        )
        return json.encodeToString(SerializationWrapper.serializer(), wrapper).toByteArray()
    }

    override fun deserialize(bytes: ByteArray?): Any? {
        if (bytes == null) return null
        val wrapper = json.decodeFromString(SerializationWrapper.serializer(), String(bytes))
        val kClass = Class.forName(wrapper.type).kotlin
        val serializer = json.serializersModule.serializer(kClass.java)
        return json.decodeFromString(serializer, wrapper.data)
    }
}


