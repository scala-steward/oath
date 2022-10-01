package oath.model

final case class Token[+H, +P](header: Option[H], payload: Option[P], signature: String)
