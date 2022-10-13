package oath.testkit

import com.auth0.jwt.algorithms.Algorithm
import oath.config.IssuerConfig
import oath.config.IssuerConfig.RegisteredConfig
import org.scalacheck.{Arbitrary, Gen}

import scala.concurrent.duration.Duration

trait Arbitraries {

  val genPositiveFiniteDuration = Gen.posNum[Long].map(Duration.fromNanos)

  implicit val issuerConfigArbitrary: Arbitrary[IssuerConfig] = Arbitrary {
    for {
      issuerClaim         <- Gen.option(Gen.alphaStr)
      subjectClaim        <- Gen.option(Gen.alphaStr)
      audienceClaim       <- Gen.listOf(Gen.alphaStr)
      includeJwtIdClaim   <- Arbitrary.arbitrary[Boolean]
      includeIssueAtClaim <- Arbitrary.arbitrary[Boolean]
      expiresAtOffset     <- Gen.option(genPositiveFiniteDuration)
      notBeforeOffset     <- Gen.option(genPositiveFiniteDuration)
      registered = RegisteredConfig(issuerClaim,
                                    subjectClaim,
                                    audienceClaim,
                                    includeJwtIdClaim,
                                    includeIssueAtClaim,
                                    expiresAtOffset,
                                    notBeforeOffset)
    } yield IssuerConfig(Algorithm.none(), registered)
  }

}
