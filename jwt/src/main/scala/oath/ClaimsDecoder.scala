package oath

import oath.model.JwtVerifyError

trait ClaimsDecoder[T] {
  def decode(token: String): Either[JwtVerifyError.DecodingError, T]
}
