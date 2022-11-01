package oath.testkit

import java.time.Instant

import com.auth0.jwt.algorithms.Algorithm
import eu.timepit.refined.types.string.NonEmptyString
import oath.NestedHeader.SimpleHeader
import oath.NestedPayload.SimplePayload
import oath.config.IssuerConfig.RegisteredConfig
import oath.config.VerifierConfig.{LeewayWindowConfig, ProvidedWithConfig}
import oath.config.{IssuerConfig, VerifierConfig}
import oath.model.RegisteredClaims
import oath.{NestedHeader, NestedPayload}
import org.scalacheck.{Arbitrary, Gen}

import scala.concurrent.duration.Duration

import scala.concurrent.duration.DurationInt

trait Arbitraries {

  val genPositiveFiniteDuration        = Gen.posNum[Long].map(Duration.fromNanos)
  val genPositiveFiniteDurationSeconds = Gen.posNum[Int].map(_.seconds)
  val genNonEmptyString =
    Gen.nonEmptyListOf[Char](Gen.alphaChar).map(_.mkString).map(NonEmptyString.unsafeFrom)

  implicit lazy val arbInstant: Arbitrary[Instant] = Arbitrary(
    Gen.chooseNum(Long.MinValue, Long.MaxValue).map(Instant.ofEpochMilli)
  )

  implicit val issuerConfigArbitrary: Arbitrary[IssuerConfig] = Arbitrary {
    for {
      issuerClaim         <- Gen.option(genNonEmptyString)
      subjectClaim        <- Gen.option(genNonEmptyString)
      audienceClaims      <- Gen.listOf(genNonEmptyString)
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
      issuerClaim    <- Gen.option(genNonEmptyString)
      subjectClaim   <- Gen.option(genNonEmptyString)
      audienceClaims <- Gen.listOf(genNonEmptyString)
      presenceClaims <- Gen.listOf(genNonEmptyString).map(_.diff(audienceClaims))
      nullClaims     <- Gen.listOf(genNonEmptyString).map(_.diff(audienceClaims ++ presenceClaims))
      leeway         <- Gen.option(genPositiveFiniteDurationSeconds)
      issuedAt       <- Gen.option(genPositiveFiniteDurationSeconds)
      expiresAt      <- Gen.option(genPositiveFiniteDurationSeconds)
      notBefore      <- Gen.option(genPositiveFiniteDurationSeconds)
      leewayWindow = LeewayWindowConfig(leeway, issuedAt, expiresAt, notBefore)
      providedWith = ProvidedWithConfig(issuerClaim, subjectClaim, audienceClaims, presenceClaims, nullClaims)
    } yield VerifierConfig(Algorithm.none(), providedWith, leewayWindow)
  }

  implicit val registeredClaimsArbitrary: Arbitrary[RegisteredClaims] = Arbitrary {
    for {
      iss <- Gen.option(genNonEmptyString)
      sub <- Gen.option(genNonEmptyString)
      aud <- Gen.listOf(genNonEmptyString)
      exp <- Gen.option(arbInstant.arbitrary)
      nbf <- Gen.option(arbInstant.arbitrary)
      iat <- Gen.option(arbInstant.arbitrary)
      jti <- Gen.option(genNonEmptyString)
    } yield RegisteredClaims(iss, sub, aud, exp, nbf, iat, jti)
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
