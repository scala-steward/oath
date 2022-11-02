package oath

trait ClaimsEncoder[P] {
  def encode(data: P): String
}
