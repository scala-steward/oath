package oath

import com.auth0.jwt.{JWT, JWTCreator}
import oath.config.VerifierConfig
import oath.testkit.{AnyWordSpecBase, PropertyBasedTesting}
import oath.utils.ClockHelper

import scala.util.chaining.scalaUtilChainingOps

class JwtVerifierSpec extends AnyWordSpecBase with PropertyBasedTesting with ClockHelper {

  "JwtVerifier" should {

    "verify token with prerequisite configurations" in forAll { config: VerifierConfig =>
      val token = JWT.create()
        .tap(builder => config.providedWith.issuerClaim.map(builder.withIssuer))
        .tap(builder => config.providedWith.subjectClaim.map(builder.withSubject))
        .tap(builder => config.providedWith.audienceClaims.map(builder.withAudience(_)))
        .tap(builder => config.providedWith.presenceClaims.map(builder.withClaim(_,"value")))
        .tap(builder => config.leewayWindow.leeway.map(_ => builder.withIssuedAt(now)))
        .tap(builder => config.leewayWindow.notBefore..map(_ => builder.withIssuedAt(now)))
        .tap(builder => config.providedWith.presenceClaims.map(builder.withClaim(_,"value")))
        .withIssuer()
        .sign(config.algorithm)

    }
  }
}
