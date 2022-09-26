package oath

trait ClaimsEncoder[T] {
  def encode(data: T): Map[String, AnyRef]
}
