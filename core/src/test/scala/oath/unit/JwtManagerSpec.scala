package oath.unit

import oath.old.TokenConfig.{JWSConfig, TokenConfig, PayloadConfig, VerifierConfig}
import oath.model.JwtClaims
import oath.testkit.AnyWordSpecBase
import oath.{ClaimsDecoder, ClaimsEncoder, JWTManager}

import cats.implicits.catsSyntaxEitherId
import cats.implicits.catsSyntaxOptionId
import oath.old.TokenConfig

class JwtManagerSpec extends AnyWordSpecBase{

  val jwsConfig = JWSConfig()
  val payloadConfig = PayloadConfig()
  val verifierConfig = VerifierConfig()
  val jwtConfig = TokenConfig(jwsConfig,payloadConfig,verifierConfig)
  val config = TokenConfig(jwtConfig)

  final case class UserClaims(id: String, age: Int)

  val jwtClaims = JwtClaims(None,Some(UserClaims("andre",18)))

  implicit def covertToOptionalClaimEncoder[T](encoder: ClaimsEncoder[T]): Option[ClaimsEncoder[T]] = encoder.some

  implicit lazy val userClaimsEncoder: ClaimsEncoder[UserClaims] =  data => Map("id" -> data.id, "age" -> data.age)
  implicit lazy val userClaimsDecoder: ClaimsDecoder[UserClaims] = _ => UserClaims("",2).asRight

  "OathManager" when {

    "issue a Token" should {

      "" in {
        val oathManager = new JWTManager(config)


        oathManager.issueJWT(jwtClaims)
      }
    }

    "verify token" should {

      "" in {
        val oathManager = new JWTManager(config)

        val jwt = oathManager.issueJWT(jwtClaims)
        oathManager.verifyJWT[Null,UserClaims](jwt.toOption.value.signature)
        oathManager.verifyJWT[UserClaims](jwt.toOption.value.signature)
      }
    }
  }


}
