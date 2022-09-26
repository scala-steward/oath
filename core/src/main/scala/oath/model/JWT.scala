package oath.model

final case class JWT[H, P](header: Option[H], payload: Option[P], signature: String)
