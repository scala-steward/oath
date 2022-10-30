package oath.model

sealed trait JwtClaims

object JwtClaims {

  case object NoClaims extends JwtClaims

  final case class JwtClaimsP[+P](payload: P, registeredClaims: RegisteredClaims) extends JwtClaims

  final case class JwtClaimsH[+H](header: H, registeredClaims: RegisteredClaims) extends JwtClaims

  final case class JwtClaimsHP[+H, +P](header: H, payload: P, registeredClaims: RegisteredClaims) extends JwtClaims
}
