package oath

import oath.NestedPayload.SimplePayload
import oath.model.JwtVerifyError.DecodingError
import oath.syntax._

import scala.jdk.CollectionConverters._

final case class NestedPayload(name: String, mapping: Map[String, SimplePayload])

object NestedPayload {
  final case class SimplePayload(name: String, data: List[String])

  implicit val nestedPayloadEncoder: ClaimsEncoder[NestedPayload] = nestedPayload =>
    Map(
      "name" -> nestedPayload.name,
      "mapping" -> nestedPayload.mapping.view
        .mapValues(value => Map("name" -> value.name, "data" -> value.data.asJava).asJava)
        .toMap
        .asJava
    ).asJava

  implicit val nestedPayloadDecoder: ClaimsDecoder[NestedPayload] = decodedJwt => {
    val name =
      decodedJwt.getClaim("name").asOptionString.toRight(DecodingError(Seq("name"), "Fail to decode NestedPayload."))
    val mappingClaim = decodedJwt.getClaim("mapping").asMap()
    val x = mappingClaim.asScala.toMap.collect { case (key, value: java.util.Map[_, _]) =>
      val map = value.asScala.toMap.map { case (k, v) => k.asInstanceOf[String] -> v }
      key -> SimplePayload(map("name").asInstanceOf[String],
                           map("data").asInstanceOf[java.util.ArrayList[String]].asScala.toList)
    }

    if (name.exists(_ == "boom")) throw new RuntimeException("boom")
    name.map(NestedPayload(_, x))
  }

}
