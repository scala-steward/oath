package oath.model

final case class JWTClaims[H, P](header: Option[H], payload: Option[P])
