package oath.model

final case class ClaimsP[+P](payload: P, registered: RegisteredClaims = RegisteredClaims.empty)
