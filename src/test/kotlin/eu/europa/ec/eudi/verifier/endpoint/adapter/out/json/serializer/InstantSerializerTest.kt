package eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.serializer

import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals

@VerifierApplicationTest(classes = [InstantSerializer::class])
internal class InstantSerializerTest {
    private val instant = Instant.ofEpochSecond(12345L)
    private val serializer = Json {
        serializersModule = SerializersModule {
            contextual(Instant::class, InstantSerializer)
        }
    }

    @Test
    fun `test serialization of Instant to String`() {
        val encoded = serializer.encodeToString(InstantSerializer, instant)

        assertEquals("12345000", encoded)
    }

    @Test
    fun `test deserialization of String to Instant`() {
        val decoded = serializer.decodeFromString<Instant>("12345000")

        assertEquals(instant, decoded)
    }
}
