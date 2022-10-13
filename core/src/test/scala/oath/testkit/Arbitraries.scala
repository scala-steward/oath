package oath.testkit

import com.auth0.jwt.algorithms.Algorithm
import oath.NestedHeader.SimpleHeader
import oath.NestedPayload.SimplePayload
import oath.config.IssuerConfig
import oath.config.IssuerConfig.RegisteredConfig
import oath.{NestedHeader, NestedPayload}
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

  implicit val simplePayloadArbitrary: Arbitrary[SimplePayload] = Arbitrary {
    for {
      name <- Gen.alphaStr
      data <- Gen.listOf(Gen.alphaStr)
    } yield SimplePayload(name, data)
  }

  implicit val simpleHeaderArbitrary: Arbitrary[SimpleHeader] = Arbitrary {
    for {
      name <- Gen.alphaStr
      data <- Gen.listOf(Gen.alphaStr)
    } yield SimpleHeader(name, data)
  }

  implicit val nestedPayloadArbitrary: Arbitrary[NestedPayload] = Arbitrary {
    for {
      name    <- Gen.alphaStr
      mapping <- Gen.mapOf(Gen.alphaStr.flatMap(str => simplePayloadArbitrary.arbitrary.map((str, _))))
    } yield NestedPayload(name, mapping)
  }

  implicit val nestedHeaderArbitrary: Arbitrary[NestedHeader] = Arbitrary {
    for {
      name    <- Gen.alphaStr
      mapping <- Gen.mapOf(Gen.alphaStr.flatMap(str => simpleHeaderArbitrary.arbitrary.map((str, _))))
    } yield NestedHeader(name, mapping)
  }
}
