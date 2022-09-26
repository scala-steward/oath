package oath

import com.auth0.jwt.interfaces.Claim

trait ClaimsDecoder[T] {
  def decode(mapping: Map[String, Claim]): T
}
