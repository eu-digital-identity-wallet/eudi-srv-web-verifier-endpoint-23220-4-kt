package eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.serializer

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionData
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure

object TransactionDataNonEmptyListSerializer : KSerializer<NonEmptyList<TransactionData>> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("NonEmptyList") {
            element("list", listSerialDescriptor<TransactionData>())
        }

    override fun serialize(encoder: Encoder, value: NonEmptyList<TransactionData>) {
        val list = value.toList()
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, ListSerializer(TransactionData.serializer()), list)
        }
    }

    override fun deserialize(decoder: Decoder): NonEmptyList<TransactionData> {
        val list = decoder.decodeStructure(descriptor) {
            var listValue: List<TransactionData>? = null
            while (true) {
                when (val index = decodeElementIndex(descriptor)) {
                    0 -> listValue =
                        decodeSerializableElement(descriptor, 0, ListSerializer(TransactionData.serializer()))

                    CompositeDecoder.DECODE_DONE -> break
                    else -> error("Unexpected index: $index")
                }
            }
            listValue ?: error("Missing list value")
        }
        return list.toNonEmptyListOrNull()!!
    }
}
