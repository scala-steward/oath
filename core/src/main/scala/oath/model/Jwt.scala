package oath.model

final case class Jwt(claims: JwtClaims, token: String)
