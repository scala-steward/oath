package oath

import cats.implicits.catsSyntaxEitherId
import com.auth0.jwt.interfaces.DecodedJWT
import oath.model.VerifyJWTError

trait ClaimsDecoder[T] {
  def decode(decodedJWT: DecodedJWT): Either[VerifyJWTError.DecodingError, T]
}

object ClaimsDecoder {

  implicit val emptyClaimDecoder: ClaimsDecoder[Null] = _ => null.asRight[VerifyJWTError.DecodingError]
}
