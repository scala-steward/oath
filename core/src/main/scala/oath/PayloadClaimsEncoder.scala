package oath

trait PayloadClaimsEncoder[P] {
  def encode(data: P): Map[String, Any]
}