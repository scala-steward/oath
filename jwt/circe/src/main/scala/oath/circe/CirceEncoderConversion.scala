package oath.circe

import io.circe.Encoder
import oath.ClaimsEncoder

import io.circe.syntax.EncoderOps

trait CirceEncoderConversion {

  implicit def circeEncoderConversion[A](implicit encoder: Encoder[A]): ClaimsEncoder[A] = data => data.asJson.noSpaces
}
