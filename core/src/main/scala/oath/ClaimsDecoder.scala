package oath

import com.auth0.jwt.interfaces.DecodedJWT
import oath.model.DecodeError

trait ClaimsDecoder[T] {
  def decode(decodedJWT: DecodedJWT): Either[DecodeError, T]
}