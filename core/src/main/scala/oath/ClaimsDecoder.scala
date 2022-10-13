package oath

import com.auth0.jwt.interfaces.DecodedJWT
import oath.model.VerifyJwtError

trait ClaimsDecoder[T] {
  def decode(decodedJwt: DecodedJWT): Either[VerifyJwtError, T]
}
