package oath

import oath.NestedPayload.SimplePayload

import scala.jdk.CollectionConverters._

import cats.implicits.catsSyntaxEitherId

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
    val name         = decodedJwt.getClaim("name").asString()
    val mappingClaim = decodedJwt.getClaim("mapping").asMap()
    val x = mappingClaim.asScala.toMap.collect { case (key, value: java.util.Map[_, _]) =>
      val map = value.asScala.toMap.map{ case (k,v) => k.asInstanceOf[String] -> v}
      key -> SimplePayload(map("name").asInstanceOf[String],
                           map("data").asInstanceOf[java.util.ArrayList[String]].asScala.toList)
    }

    NestedPayload(name, x).asRight
  }

}
