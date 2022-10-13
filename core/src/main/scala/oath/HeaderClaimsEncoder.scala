package oath

trait HeaderClaimsEncoder[H] {
  def encode(data: H): Map[String, AnyRef]
}
