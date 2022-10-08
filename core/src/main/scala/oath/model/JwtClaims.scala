package oath.model

sealed trait JwtClaims

object JwtClaims {

  case object NoClaims extends JwtClaims

  final case class JwtClaimsP[+P](payload: P) extends JwtClaims

  final case class JwtClaimsH[+H](header: H) extends JwtClaims

  final case class JwtClaimsHP[+H, +P](header: H, payload: P) extends JwtClaims
}
