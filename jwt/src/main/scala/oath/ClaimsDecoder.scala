package oath

import com.auth0.jwt.interfaces.DecodedJWT
import oath.model.JwtVerifyError

trait ClaimsDecoder[T] {
  def decode(decodedJwt: DecodedJWT): Either[JwtVerifyError.DecodingError, T]
}
