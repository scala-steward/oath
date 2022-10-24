package oath

trait ClaimsEncoder[P] {
  def encode(data: P): java.util.Map[String, Object]
}
