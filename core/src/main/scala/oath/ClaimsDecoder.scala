package oath

import oath.model.VerifyJwtError

trait ClaimsDecoder[T] {
  def decode(decodedJwt: String): Either[VerifyJwtError, T]
}
