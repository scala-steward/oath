package oath.model

final case class TokenClaims[+H, +P](header: Option[H], payload: Option[P])
