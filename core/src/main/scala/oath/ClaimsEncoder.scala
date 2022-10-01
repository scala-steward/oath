package oath

trait ClaimsEncoder[T] {
  def encode(data: T): Map[String, Any]
}

object ClaimsEncoder{

  implicit val emptyClaimEncoder: ClaimsEncoder[Nothing] = _ => Map.empty[String, Any]
}