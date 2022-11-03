package oath

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import eu.timepit.refined.types.string.NonEmptyString
import oath.NestedHeader._
import oath.NestedPayload._
import oath.config.VerifierConfig
import oath.config.VerifierConfig.{LeewayWindowConfig, ProvidedWithConfig}
import oath.model._
import oath.testkit.{AnyWordSpecBase, PropertyBasedTesting}
import oath.utils.ClockHelper

import cats.implicits.catsSyntaxEitherId
import cats.implicits.catsSyntaxOptionId
import scala.jdk.CollectionConverters.MapHasAsJava
import scala.util.chaining.scalaUtilChainingOps

class JwtVerifierSpec extends AnyWordSpecBase with PropertyBasedTesting with ClockHelper {

  val defaultConfig =
    VerifierConfig(Algorithm.none(), ProvidedWithConfig(None, None, Nil), LeewayWindowConfig(None, None, None, None))

  "JwtVerifier" should {

    "verify token with prerequisite configurations" in forAll { config: VerifierConfig =>
      val jwtVerifier = new JwtVerifier(config)

      val token = JWT
        .create()
        .tap(builder => config.providedWith.issuerClaim.map(nonEmptyString => builder.withIssuer(nonEmptyString.value)))
        .tap(builder =>
          config.providedWith.subjectClaim.map(nonEmptyString => builder.withSubject(nonEmptyString.value)))
        .tap(builder => builder.withAudience(config.providedWith.audienceClaims.map(_.value): _*))
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

      val verified = jwtVerifier.verifyJwt(JwtToken.Token(NonEmptyString.unsafeFrom(token))).toOption

      verified should not be empty
    }

    "verify a token with header" in forAll { nestedHeader: NestedHeader =>
      val token = JWT
        .create()
        .withHeader(
          Map(dataField -> nestedHeaderEncoder.encode(nestedHeader)).asJava.asInstanceOf[java.util.Map[String, Object]])
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified    = jwtVerifier.verifyJwt[NestedHeader](JwtToken.TokenH(NonEmptyString.unsafeFrom(token)))

      verified.value shouldBe JwtClaims.ClaimsH(nestedHeader)
    }

    "verify a token with payload" in forAll { nestedPayload: NestedPayload =>
      val token = JWT
        .create()
        .withPayload(Map(dataField -> nestedPayloadEncoder.encode(nestedPayload)).asJava)
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified    = jwtVerifier.verifyJwt[NestedPayload](JwtToken.TokenP(NonEmptyString.unsafeFrom(token)))

      verified.value shouldBe JwtClaims.ClaimsP(nestedPayload)
    }

    "verify a token with header & payload" in forAll { (nestedPayload: NestedPayload, nestedHeader: NestedHeader) =>
      val token = JWT
        .create()
        .withPayload(Map(dataField -> nestedPayloadEncoder.encode(nestedPayload)).asJava)
        .withHeader(
          Map(dataField -> nestedHeaderEncoder.encode(nestedHeader)).asJava.asInstanceOf[java.util.Map[String, Object]])
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified =
        jwtVerifier.verifyJwt[NestedHeader, NestedPayload](JwtToken.TokenHP(NonEmptyString.unsafeFrom(token)))

      verified.value shouldBe JwtClaims.ClaimsHP(nestedHeader, nestedPayload)
    }

    "fail to decode a token with header" in {
      val header = """{"name": "name"}"""
      val token = JWT
        .create()
        .withHeader(Map(dataField -> header).asJava.asInstanceOf[java.util.Map[String, Object]])
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified    = jwtVerifier.verifyJwt[NestedHeader](JwtToken.TokenH(NonEmptyString.unsafeFrom(token)))

      verified shouldBe Left(JwtVerifyError.DecodingError("Missing required field: DownField(mapping)", null))
    }

    "fail to decode a token with payload" in {
      val payload = """{"name": "name"}"""
      val token = JWT
        .create()
        .withPayload(Map(dataField -> payload).asJava)
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified    = jwtVerifier.verifyJwt[NestedPayload](JwtToken.TokenP(NonEmptyString.unsafeFrom(token)))

      verified shouldBe Left(JwtVerifyError.DecodingError("Missing required field: DownField(mapping)", null))
    }

    "fail to decode a token with header & payload" in {
      val header  = """{"name": "name"}"""
      val payload = """{"name": "name"}"""
      val token = JWT
        .create()
        .withHeader(Map(dataField -> header).asJava.asInstanceOf[java.util.Map[String, Object]])
        .withPayload(Map(dataField -> payload).asJava)
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified =
        jwtVerifier.verifyJwt[NestedHeader, NestedPayload](JwtToken.TokenHP(NonEmptyString.unsafeFrom(token)))

      verified shouldBe Left(
        JwtVerifyError.DecodingErrors(
          JwtVerifyError.DecodingError("Missing required field: DownField(mapping)", null).some,
          JwtVerifyError.DecodingError("Missing required field: DownField(mapping)", null).some
        ))
    }

    "fail to decode a token with header if exception raised in decoder" in {
      val token = JWT
        .create()
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified    = jwtVerifier.verifyJwt[SimpleHeader](JwtToken.TokenH(NonEmptyString.unsafeFrom(token)))

      verified.left.value.error shouldBe "Boom"
    }

    "fail to decode a token with payload if exception raised in decoder" in {
      val token = JWT
        .create()
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified    = jwtVerifier.verifyJwt[SimplePayload](JwtToken.TokenP(NonEmptyString.unsafeFrom(token)))

      verified.left.value.error shouldBe "Boom"
    }

    "fail to decode a token with header & payload if exception raised in decoder" in {
      val token = JWT
        .create()
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified =
        jwtVerifier.verifyJwt[SimpleHeader, SimplePayload](JwtToken.TokenHP(NonEmptyString.unsafeFrom(token)))

      verified.left.value.error shouldBe "JWT Failed to decode both parts: \nheader decoding error: Boom \npayload decoding error: Boom"
    }

    "fail to verify token with VerificationError when provided with claims are not meet criteria" in {
      val config = defaultConfig.copy(providedWith =
        defaultConfig.providedWith.copy(issuerClaim = Some(NonEmptyString.unsafeFrom("issuer"))))
      val token = JWT
        .create()
        .sign(config.algorithm)

      val jwtVerifier = new JwtVerifier(config)
      val verified    = jwtVerifier.verifyJwt(JwtToken.Token(NonEmptyString.unsafeFrom(token)))

      verified shouldBe JwtVerifyError.VerificationError("The Claim 'iss' is not present in the JWT.").asLeft
    }

    "fail to verify token with IllegalArgument when null algorithm is provided" in forAll { config: VerifierConfig =>
      val token = JWT
        .create()
        .sign(config.algorithm)

      val jwtVerifier = new JwtVerifier(config.copy(algorithm = null))

      val verified = jwtVerifier.verifyJwt(JwtToken.Token(NonEmptyString.unsafeFrom(token)))

      verified shouldBe JwtVerifyError.IllegalArgument("The Algorithm cannot be null.").asLeft
    }

    "fail to verify token with AlgorithmMismatch when jwt header algorithm doesn't match with verify" in forAll {
      config: VerifierConfig =>
        val token = JWT
          .create()
          .sign(config.algorithm)

        val jwtVerifier = new JwtVerifier(config.copy(algorithm = Algorithm.HMAC256("secret")))
        val verified    = jwtVerifier.verifyJwt(JwtToken.Token(NonEmptyString.unsafeFrom(token)))

        verified shouldBe
          JwtVerifyError
            .AlgorithmMismatch("The provided Algorithm doesn't match the one defined in the JWT's Header.")
            .asLeft
    }

    "fail to verify token with SignatureVerificationError when secrets provided are wrong" in forAll {
      config: VerifierConfig =>
        val token = JWT
          .create()
          .sign(Algorithm.HMAC256("secret1"))

        val jwtVerifier = new JwtVerifier(config.copy(algorithm = Algorithm.HMAC256("secret2")))
        val verified    = jwtVerifier.verifyJwt(JwtToken.Token(NonEmptyString.unsafeFrom(token)))

        verified shouldBe
          JwtVerifyError
            .SignatureVerificationError(
              "The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256")
            .asLeft
    }

    "fail to verify token with TokenExpired when JWT expires" in {
      val expiresAt = now.minusSeconds(1)
      val token = JWT
        .create()
        .withExpiresAt(expiresAt)
        .sign(defaultConfig.algorithm)

      val jwtVerifier = new JwtVerifier(defaultConfig)
      val verified    = jwtVerifier.verifyJwt(JwtToken.Token(NonEmptyString.unsafeFrom(token)))

      verified shouldBe
        JwtVerifyError
          .TokenExpired(s"The Token has expired on $expiresAt.")
          .asLeft
    }
  }
}
