package oath.config

import com.auth0.jwt.algorithms.Algorithm

import java.security.{KeyFactory, PrivateKey, PublicKey}

object JWSConfigLoader {

  val keyFactory = KeyFactory.getInstance("RSA")

  def loadOrFailAlgorithm(alg: String) = alg.trim.toUpperCase match {
    case "HS256" => Algorithm.HMAC256("")
    case "HS384" => Algorithm.HMAC384("")
    case "HS512" => Algorithm.HMAC512("")
    case "RS256" => Algorithm.RSA256("", "")
    case "RS384" => Algorithm.RSA384("", "")
    case "RS512" => Algorithm.RSA512("", "")
    case "ES256" => Algorithm.ECDSA256("","")
    case "ES384" => Algorithm.ECDSA384("","")
    case "ES512" => Algorithm.ECDSA512("","")
  }

}
