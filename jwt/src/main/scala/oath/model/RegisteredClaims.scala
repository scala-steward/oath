package oath.model

import eu.timepit.refined.types.string.NonEmptyString

import java.time.Instant

final case class RegisteredClaims(
    iss: Option[NonEmptyString],
    sub: Option[NonEmptyString],
    aud: Seq[NonEmptyString],
    exp: Option[Instant],
    nbf: Option[Instant],
    iat: Option[Instant],
    jti: Option[NonEmptyString]
)

object RegisteredClaims {

  def empty: RegisteredClaims = RegisteredClaims(
    None,
    None,
    Seq.empty,
    None,
    None,
    None,
    None
  )
}
