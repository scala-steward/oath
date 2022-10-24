package oath

import oath.NestedHeader.SimpleHeader
import oath.model.JwtVerifyError.DecodingError
import oath.syntax._

import scala.jdk.CollectionConverters._

final case class NestedHeader(name: String, mapping: Map[String, SimpleHeader])

object NestedHeader {
  final case class SimpleHeader(name: String, data: List[String])

  implicit val nestedHeaderEncoder: ClaimsEncoder[NestedHeader] = nestedHeader =>
    Map(
      "name" -> nestedHeader.name,
      "mapping" -> nestedHeader.mapping.view
        .mapValues(value => Map("name" -> value.name, "data" -> value.data.asJava).asJava)
        .toMap
        .asJava
    ).asJava

  implicit val nestedHeaderDecoder: ClaimsDecoder[NestedHeader] = decodedJwt => {
    val name = decodedJwt
      .getHeaderClaim("name")
      .asOptionString
      .toRight(DecodingError(Seq("name"), "Fail to decode NestedHeader."))
    val mappingClaim = decodedJwt.getHeaderClaim("mapping").asMap()
    val x = mappingClaim.asScala.toMap.collect { case (key, value: java.util.Map[_, _]) =>
      val map = value.asScala.toMap.collect { case (k, v) => k.asInstanceOf[String] -> v }
      key -> SimpleHeader(map("name").asInstanceOf[String],
                          map("data").asInstanceOf[java.util.ArrayList[String]].asScala.toList)
    }

    if (name.exists(_ == "boom")) throw new RuntimeException("boom")
    name.map(NestedHeader(_, x))
  }

}
