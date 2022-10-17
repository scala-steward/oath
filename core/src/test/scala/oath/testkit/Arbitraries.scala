package oath.testkit

import com.auth0.jwt.algorithms.Algorithm
import oath.NestedHeader.SimpleHeader
import oath.NestedPayload.SimplePayload
import oath.config.{IssuerConfig, VerifierConfig}
import oath.config.IssuerConfig.RegisteredConfig
import oath.config.VerifierConfig.{LeewayWindowConfig, ProvidedWithConfig}
import oath.{NestedHeader, NestedPayload}
import org.scalacheck.{Arbitrary, Gen}

import scala.concurrent.duration.Duration

trait Arbitraries {

  val genPositiveFiniteDuration = Gen.posNum[Long].map(Duration.fromNanos)

  implicit val issuerConfigArbitrary: Arbitrary[IssuerConfig] = Arbitrary {
    for {
      issuerClaim         <- Gen.option(Gen.alphaStr)
      subjectClaim        <- Gen.option(Gen.alphaStr)
      audienceClaims      <- Gen.listOf(Gen.alphaStr)
      includeJwtIdClaim   <- Arbitrary.arbitrary[Boolean]
      includeIssueAtClaim <- Arbitrary.arbitrary[Boolean]
      expiresAtOffset     <- Gen.option(genPositiveFiniteDuration)
      notBeforeOffset     <- Gen.option(genPositiveFiniteDuration)
      registered = RegisteredConfig(issuerClaim,
                                    subjectClaim,
                                    audienceClaims,
                                    includeJwtIdClaim,
                                    includeIssueAtClaim,
                                    expiresAtOffset,
                                    notBeforeOffset)
    } yield IssuerConfig(Algorithm.none(), registered)
  }

  implicit val verifierConfigArbitrary: Arbitrary[VerifierConfig] = Arbitrary {
    for {
      issuerClaim    <- Gen.option(Gen.alphaStr)
      subjectClaim   <- Gen.option(Gen.alphaStr)
      audienceClaims <- Gen.listOf(Gen.alphaStr)
      presenceClaims <- Gen.listOf(Gen.alphaStr).map(_.diff(audienceClaims))
      nullClaims     <- Gen.listOf(Gen.alphaStr).map(_.diff(audienceClaims ++ presenceClaims))
      leeway         <- Gen.option(genPositiveFiniteDuration)
      issuedAt       <- Gen.option(genPositiveFiniteDuration)
      expiresAt      <- Gen.option(genPositiveFiniteDuration)
      notBefore      <- Gen.option(genPositiveFiniteDuration)
      leewayWindow = LeewayWindowConfig(leeway, issuedAt, expiresAt, notBefore)
      providedWith = ProvidedWithConfig(issuerClaim, subjectClaim, audienceClaims, presenceClaims, nullClaims)
    } yield VerifierConfig(Algorithm.none(), providedWith, leewayWindow)
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
