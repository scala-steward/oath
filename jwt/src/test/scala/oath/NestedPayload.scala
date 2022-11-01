package oath

import io.circe.generic.semiauto._
import io.circe.parser._
import io.circe.syntax._
import io.circe.{Decoder, Encoder}
import oath.NestedPayload.SimplePayload
import oath.model.JwtVerifyError

final case class NestedPayload(name: String, mapping: Map[String, SimplePayload])

object NestedPayload {
  final case class SimplePayload(name: String, data: List[String])

  implicit val simplePayloadCirceEncoder: Encoder[SimplePayload] = deriveEncoder[SimplePayload]
  implicit val simplePayloadCirceDecoder: Decoder[SimplePayload] = deriveDecoder[SimplePayload]

  implicit val nestedPayloadCirceEncoder: Encoder[NestedPayload] = deriveEncoder[NestedPayload]
  implicit val nestedPayloadCirceDecoder: Decoder[NestedPayload] = deriveDecoder[NestedPayload]

  implicit val nestedPayloadEncoder: ClaimsEncoder[NestedPayload] = nestedPayload => nestedPayload.asJson.noSpaces
  implicit val nestedPayloadDecoder: ClaimsDecoder[NestedPayload] = nestedPayloadJson =>
    parse(nestedPayloadJson).left
      .map(parsingFailure => JwtVerifyError.DecodingError(parsingFailure.message, parsingFailure.underlying))
      .flatMap(_.as[NestedPayload].left.map(decodingFailure =>
        JwtVerifyError.DecodingError(decodingFailure.getMessage(), decodingFailure.getCause)))
}
