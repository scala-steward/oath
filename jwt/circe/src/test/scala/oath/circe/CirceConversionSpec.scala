package oath.circe

import com.auth0.jwt.algorithms.Algorithm
import oath.config.IssuerConfig.RegisteredConfig
import oath.config.VerifierConfig.{LeewayWindowConfig, ProvidedWithConfig}
import oath.config.{IssuerConfig, VerifierConfig}
import oath.model.{JwtClaims, JwtToken}
import oath.testkit.AnyWordSpecBase
import oath.{JwtIssuer, JwtVerifier}

class CirceConversionSpec extends AnyWordSpecBase {

  val verifierConfig =
    VerifierConfig(Algorithm.none(), ProvidedWithConfig(None, None, Nil), LeewayWindowConfig(None, None, None, None))
  val issuerConfig =
    IssuerConfig(Algorithm.none(), RegisteredConfig(None, None, Nil, false, false, None, None))

  val jwtVerifier = new JwtVerifier(verifierConfig)
  val jwtIssuer   = new JwtIssuer(issuerConfig)

  "CirceConversion" should {

    "convert circe (encoders & decoders) to claims (encoders & decoders)" in {
      val bar    = Bar("bar", 10)
      val jwt    = jwtIssuer.issueJwt(JwtClaims.ClaimsP(bar)).value
      val claims = jwtVerifier.verifyJwt[Bar](JwtToken.TokenP(jwt.token)).value

      claims.payload shouldBe bar
    }

    "convert circe (codec) to claims (encoders & decoders)" in {
      val foo = Foo("foo", 10)
      val jwt = jwtIssuer.issueJwt(JwtClaims.ClaimsP(foo)).value
      val claims = jwtVerifier.verifyJwt[Foo](JwtToken.TokenP(jwt.token)).value

      claims.payload shouldBe foo
    }

    //TODO: Test error scenarios
  }
}
