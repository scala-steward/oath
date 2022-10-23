package oath

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import eu.timepit.refined.auto._
import oath.config.VerifierConfig
import oath.config.VerifierConfig.{LeewayWindowConfig, ProvidedWithConfig}
import oath.model.{JwtClaims, JwtVerifyError}
import oath.testkit.{AnyWordSpecBase, PropertyBasedTesting}
import oath.utils.ClockHelper

import scala.util.chaining.scalaUtilChainingOps

class JwtVerifierSpec extends AnyWordSpecBase with PropertyBasedTesting with ClockHelper {

  "JwtVerifier" should {

    "verify token with prerequisite configurations" in forAll { config: VerifierConfig =>
      val token = JWT
        .create()
        .tap(builder => config.providedWith.issuerClaim.map(nonEmptyString => builder.withIssuer(nonEmptyString.value)))
        .tap(builder =>
          config.providedWith.subjectClaim.map(nonEmptyString => builder.withSubject(nonEmptyString.value)))
        .tap(builder => builder.withAudience(config.providedWith.audienceClaims.map(_.value): _*))
        .tap(builder =>
          config.providedWith.presenceClaims.map(nonEmptyString => builder.withClaim(nonEmptyString.value, "value")))
        .tap(builder =>
          config.providedWith.nullClaims.map(nonEmptyString => builder.withNullClaim(nonEmptyString.value)))
        .tap(builder =>
          config.leewayWindow.leeway.map { leeway =>
            builder.withExpiresAt(now.plusSeconds(leeway.toSeconds - 1))
            builder.withIssuedAt(now.plusSeconds(leeway.toSeconds - 1))
            builder.withNotBefore(now.plusSeconds(leeway.toSeconds - 1))
          })
        .tap(builder =>
          config.leewayWindow.expiresAt.map(expiresAt =>
            builder.withExpiresAt(now.plusSeconds(expiresAt.toSeconds - 1))))
        .tap(builder =>
          config.leewayWindow.issuedAt.map(issueAt => builder.withIssuedAt(now.plusSeconds(issueAt.toSeconds - 1))))
        .tap(builder =>
          config.leewayWindow.notBefore.map(notBefore =>
            builder.withNotBefore(now.plusSeconds(notBefore.toSeconds - 1))))
        .sign(config.algorithm)

      val jwtVerifier = new JwtVerifier(config)

      val verified = jwtVerifier.verifyNoClaimsJwt(token)

      verified.value shouldBe JwtClaims.NoClaims
    }

    "fail to verify token with VerificationError" in {
      val config = VerifierConfig(Algorithm.none(),
                                  ProvidedWithConfig(issuerClaim = Some("issuer"), None, Nil, Nil, Nil),
                                  LeewayWindowConfig(None, None, None, None))
      val token = JWT
        .create()
        .sign(config.algorithm)

      val jwtVerifier = new JwtVerifier(config)

      val verified = jwtVerifier.verifyNoClaimsJwt(token)

      verified shouldBe Left(JwtVerifyError.VerificationError("The Claim 'iss' is not present in the JWT."))
    }

    "fail to verify token when algorithm is null" in {
      val config = VerifierConfig(Algorithm.none(),
                                  ProvidedWithConfig(issuerClaim = Some("issuer"), None, Nil, Nil, Nil),
                                  LeewayWindowConfig(None, None, None, None))
      val token = JWT
        .create()
        .sign(config.algorithm)

      val jwtVerifier = new JwtVerifier(config)

      val verified = jwtVerifier.verifyNoClaimsJwt(token)

      verified shouldBe Left(JwtVerifyError.VerificationError("The Claim 'iss' is not present in the JWT."))
    }
  }
}
