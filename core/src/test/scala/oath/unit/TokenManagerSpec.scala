package oath.unit

import oath.config.OathConfig
import oath.config.OathConfig.{JWSConfig, JWTConfig, PayloadConfig, VerifierConfig}
import oath.model.TokenClaims
import oath.testkit.AnyWordSpecBase
import oath.{ClaimsDecoder, ClaimsEncoder, TokenManager}

import cats.implicits.catsSyntaxEitherId
import cats.implicits.catsSyntaxOptionId

class TokenManagerSpec extends AnyWordSpecBase{

  val jwsConfig = JWSConfig()
  val payloadConfig = PayloadConfig()
  val verifierConfig = VerifierConfig()
  val jwtConfig = JWTConfig(jwsConfig,payloadConfig,verifierConfig)
  val config = OathConfig(jwtConfig)

  final case class UserClaims(id: String, age: Int)

  val jwtClaims = TokenClaims(None,Some(UserClaims("andre",18)))

  implicit def covertToOptionalClaimEncoder[T](encoder: ClaimsEncoder[T]): Option[ClaimsEncoder[T]] = encoder.some

  implicit lazy val userClaimsEncoder: ClaimsEncoder[UserClaims] =  data => Map("id" -> data.id, "age" -> data.age)
  implicit lazy val userClaimsDecoder: ClaimsDecoder[UserClaims] = _ => UserClaims("",2).asRight

  "OathManager" when {

    "issue a Token" should {

      "" in {
        val oathManager = new TokenManager(config)


        oathManager.issueJWT(jwtClaims)
      }
    }

    "verify token" should {

      "" in {
        val oathManager = new TokenManager(config)

        val jwt = oathManager.issueJWT(jwtClaims)
        oathManager.verifyJWT[Null,UserClaims](jwt.toOption.value.signature)
      }
    }
  }


}
