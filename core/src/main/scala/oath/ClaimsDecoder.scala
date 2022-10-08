package oath

import com.auth0.jwt.interfaces.DecodedJWT
import oath.model.VerifyJWTError

trait ClaimsDecoder[T] {
  def decode(decodedJWT: DecodedJWT): Either[VerifyJWTError.DecodingError, T]
}
