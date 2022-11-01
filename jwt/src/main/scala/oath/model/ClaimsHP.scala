package oath.model

final case class ClaimsHP[+H,+P](header: H, payload: P, registered: RegisteredClaims = RegisteredClaims.empty)
