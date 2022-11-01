package oath.model

final case class ClaimsH[+H](header: H, registered: RegisteredClaims = RegisteredClaims.empty)
