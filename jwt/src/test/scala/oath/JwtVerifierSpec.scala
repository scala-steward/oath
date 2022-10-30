package oath

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import eu.timepit.refined.auto._
import oath.config.VerifierConfig
import oath.config.VerifierConfig.{LeewayWindowConfig, ProvidedWithConfig}
import oath.model.{JwtClaims, JwtVerifyError}
import oath.testkit.{AnyWordSpecBase, PropertyBasedTesting}
import oath.utils.ClockHelper

import cats.implicits.catsSyntaxEitherId
import cats.implicits.catsSyntaxOptionId
import scala.jdk.CollectionConverters.MapHasAsJava
import scala.jdk.CollectionConverters.MapHasAsScala
import scala.util.chaining.scalaUtilChainingOps

class JwtVerifierSpec extends AnyWordSpecBase with PropertyBasedTesting with ClockHelper {

  val defaultConfig = VerifierConfig(Algorithm.none(),
                                     ProvidedWithConfig(None, None, Nil, Nil, Nil),
                                     LeewayWindowConfig(None, None, None, None))

  "JwtVerifier" should {

//    "verify token with prerequisite configurations" in forAll { config: VerifierConfig =>
//      val token = JWT
//        .create()
//        .tap(builder => config.providedWith.issuerClaim.map(nonEmptyString => builder.withIssuer(nonEmptyString.value)))
//        .tap(builder =>
//          config.providedWith.subjectClaim.map(nonEmptyString => builder.withSubject(nonEmptyString.value)))
//        .tap(builder => builder.withAudience(config.providedWith.audienceClaims.map(_.value): _*))
//        .tap(builder =>
//          config.providedWith.presenceClaims.map(nonEmptyString => builder.withClaim(nonEmptyString.value, "value")))
//        .tap(builder =>
//          config.providedWith.nullClaims.map(nonEmptyString => builder.withNullClaim(nonEmptyString.value)))
//        .tap(builder =>
//          config.leewayWindow.leeway.map { leeway =>
//            builder.withExpiresAt(now.plusSeconds(leeway.toSeconds - 1))
//            builder.withIssuedAt(now.plusSeconds(leeway.toSeconds - 1))
//            builder.withNotBefore(now.plusSeconds(leeway.toSeconds - 1))
//          })
//        .tap(builder =>
//          config.leewayWindow.expiresAt.map(expiresAt =>
//            builder.withExpiresAt(now.plusSeconds(expiresAt.toSeconds - 1))))
//        .tap(builder =>
//          config.leewayWindow.issuedAt.map(issueAt => builder.withIssuedAt(now.plusSeconds(issueAt.toSeconds - 1))))
//        .tap(builder =>
//          config.leewayWindow.notBefore.map(notBefore =>
//            builder.withNotBefore(now.plusSeconds(notBefore.toSeconds - 1))))
//        .sign(config.algorithm)
//
//      val jwtVerifier = new JwtVerifier(config)
//
//      val verified = jwtVerifier.verifyJwtNoClaims(token)
//
//      verified.value shouldBe JwtClaims.NoClaims
//    }
//
//    "verify a token with header" in forAll { nestedHeader: NestedHeader =>
//      val token = JWT
//        .create()
//        .withHeader(NestedHeader.nestedHeaderEncoder.encode(nestedHeader))
//        .sign(defaultConfig.algorithm)
//
//      val jwtVerifier = new JwtVerifier(defaultConfig)
//      val verified    = jwtVerifier.verifyJwtHeader[NestedHeader](token)
//
//      verified.value shouldBe JwtClaims.JwtClaimsH(nestedHeader)
//    }
//
//    "verify a token with payload" in forAll { nestedPayload: NestedPayload =>
//      val token = JWT
//        .create()
//        .withPayload(NestedPayload.nestedPayloadEncoder.encode(nestedPayload))
//        .sign(defaultConfig.algorithm)
//
//      val jwtVerifier = new JwtVerifier(defaultConfig)
//      val verified    = jwtVerifier.verifyJwtPayload[NestedPayload](token)
//
//      verified.value shouldBe JwtClaims.JwtClaimsP(nestedPayload)
//    }
//
//    "verify a token with header & payload" in forAll { (nestedPayload: NestedPayload, nestedHeader: NestedHeader) =>
//      val token = JWT
//        .create()
//        .withPayload(NestedPayload.nestedPayloadEncoder.encode(nestedPayload))
//        .withHeader(NestedHeader.nestedHeaderEncoder.encode(nestedHeader))
//        .sign(defaultConfig.algorithm)
//
//      val jwtVerifier = new JwtVerifier(defaultConfig)
//      val verified    = jwtVerifier.verifyJwt[NestedHeader, NestedPayload](token)
//
//      verified.value shouldBe JwtClaims.JwtClaimsHP(nestedHeader, nestedPayload)
//    }
//
//    "fail to decode a token with header" in forAll { nestedHeader: NestedHeader =>
//      val header = NestedHeader.nestedHeaderEncoder.encode(nestedHeader).asScala.tail
//      val token = JWT
//        .create()
//        .withHeader(header.asJava)
//        .sign(defaultConfig.algorithm)
//
//      val jwtVerifier = new JwtVerifier(defaultConfig)
//      val verified    = jwtVerifier.verifyJwtHeader[NestedHeader](token)
//
//      verified shouldBe Left(JwtVerifyError.DecodingError(Seq("name"), "Fail to decode NestedHeader."))
//    }
//
//    "fail to decode a token with payload" in forAll { nestedPayload: NestedPayload =>
//      val payload = NestedPayload.nestedPayloadEncoder.encode(nestedPayload).asScala.tail
//      val token = JWT
//        .create()
//        .withPayload(payload.asJava)
//        .sign(defaultConfig.algorithm)
//
//      val jwtVerifier = new JwtVerifier(defaultConfig)
//      val verified    = jwtVerifier.verifyJwtPayload[NestedPayload](token)
//
//      verified shouldBe Left(JwtVerifyError.DecodingError(Seq("name"), "Fail to decode NestedPayload."))
//    }
//
//    "fail to decode a token with header & payload" in forAll {
//      (nestedPayload: NestedPayload, nestedHeader: NestedHeader) =>
//        val header  = NestedHeader.nestedHeaderEncoder.encode(nestedHeader).asScala.tail
//        val payload = NestedPayload.nestedPayloadEncoder.encode(nestedPayload).asScala.tail
//        val token = JWT
//          .create()
//          .withHeader(header.asJava)
//          .withPayload(payload.asJava)
//          .sign(defaultConfig.algorithm)
//
//        val jwtVerifier = new JwtVerifier(defaultConfig)
//        val verified    = jwtVerifier.verifyJwt[NestedHeader, NestedPayload](token)
//
//        verified shouldBe Left(
//          JwtVerifyError.DecodingErrors(
//            JwtVerifyError.DecodingError(Seq("name"), "Fail to decode NestedHeader.").some,
//            JwtVerifyError.DecodingError(Seq("name"), "Fail to decode NestedPayload.").some
//          ))
//    }
//
//    "fail to decode a token with header if exception raised in decoder" in forAll { nestedHeader: NestedHeader =>
//      val token = JWT
//        .create()
//        .withHeader(NestedHeader.nestedHeaderEncoder.encode(nestedHeader.copy(name = "boom")))
//        .sign(defaultConfig.algorithm)
//
//      val jwtVerifier = new JwtVerifier(defaultConfig)
//      val verified    = jwtVerifier.verifyJwtHeader[NestedHeader](token)
//
//      verified shouldBe Left(JwtVerifyError.DecodingError(Nil, "boom"))
//    }
//
//    "fail to decode a token with payload if exception raised in decoder" in forAll { nestedPayload: NestedPayload =>
//      val token = JWT
//        .create()
//        .withPayload(NestedPayload.nestedPayloadEncoder.encode(nestedPayload.copy(name = "boom")))
//        .sign(defaultConfig.algorithm)
//
//      val jwtVerifier = new JwtVerifier(defaultConfig)
//      val verified    = jwtVerifier.verifyJwtPayload[NestedPayload](token)
//
//      verified shouldBe Left(JwtVerifyError.DecodingError(Nil, "boom"))
//    }
//
//    "fail to decode a token with header & payload if exception raised in decoder" in forAll {
//      (nestedPayload: NestedPayload, nestedHeader: NestedHeader) =>
//        val brokenNestedHeader  = nestedHeader.copy(name = "boom")
//        val brokenNestedPayload = nestedPayload.copy(name = "boom")
//        val table = Table(
//          "Input" -> "Output",
//          (brokenNestedHeader, brokenNestedPayload) -> (JwtVerifyError
//            .DecodingError(Nil, "boom")
//            .some, JwtVerifyError.DecodingError(Nil, "boom").some),
//          (brokenNestedHeader, nestedPayload) -> (JwtVerifyError.DecodingError(Nil, "boom").some, None),
//          (nestedHeader, brokenNestedPayload) -> (None, JwtVerifyError.DecodingError(Nil, "boom").some)
//        )
//
//        forAll(table) { case ((header, payload), (headerDecodingError, payloadDecodingError)) =>
//          val token = JWT
//            .create()
//            .withHeader(NestedHeader.nestedHeaderEncoder.encode(header))
//            .withPayload(NestedPayload.nestedPayloadEncoder.encode(payload))
//            .sign(defaultConfig.algorithm)
//
//          val jwtVerifier = new JwtVerifier(defaultConfig)
//          val verified    = jwtVerifier.verifyJwt[NestedHeader, NestedPayload](token)
//
//          verified shouldBe Left(
//            JwtVerifyError.DecodingErrors(
//              headerDecodingError,
//              payloadDecodingError
//            ))
//        }
//
//    }
//
//    "fail to verify token with VerificationError when provided with claims are not meet criteria" in {
//      val config = defaultConfig.copy(providedWith = defaultConfig.providedWith.copy(issuerClaim = Some("issuer")))
//      val token = JWT
//        .create()
//        .sign(config.algorithm)
//
//      val jwtVerifier = new JwtVerifier(config)
//
//      val verified = jwtVerifier.verifyJwtNoClaims(token)
//
//      verified shouldBe JwtVerifyError.VerificationError("The Claim 'iss' is not present in the JWT.").asLeft
//    }
//
//    "fail to verify token with IllegalArgument when null algorithm is provided" in forAll { config: VerifierConfig =>
//      val token = JWT
//        .create()
//        .sign(config.algorithm)
//
//      val jwtVerifier = new JwtVerifier(config.copy(algorithm = null))
//
//      val verified = jwtVerifier.verifyJwtNoClaims(token)
//
//      verified shouldBe JwtVerifyError.IllegalArgument("The Algorithm cannot be null.").asLeft
//    }
//
//    "fail to verify token with AlgorithmMismatch when jwt header algorithm doesn't match with verify" in forAll {
//      config: VerifierConfig =>
//        val token = JWT
//          .create()
//          .sign(config.algorithm)
//
//        val jwtVerifier = new JwtVerifier(config.copy(algorithm = Algorithm.HMAC256("secret")))
//
//        val verified = jwtVerifier.verifyJwtNoClaims(token)
//
//        verified shouldBe
//          JwtVerifyError
//            .AlgorithmMismatch("The provided Algorithm doesn't match the one defined in the JWT's Header.")
//            .asLeft
//    }
//
//    "fail to verify token with SignatureVerificationError when secrets provided are wrong" in forAll {
//      config: VerifierConfig =>
//        val token = JWT
//          .create()
//          .sign(Algorithm.HMAC256("secret1"))
//
//        val jwtVerifier = new JwtVerifier(config.copy(algorithm = Algorithm.HMAC256("secret2")))
//
//        val verified = jwtVerifier.verifyJwtNoClaims(token)
//
//        verified shouldBe
//          JwtVerifyError
//            .SignatureVerificationError(
//              "The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256")
//            .asLeft
//    }
//
//    "fail to verify token with TokenExpired when JWT expires" in {
//      val expiresAt = now.minusSeconds(1)
//      val token = JWT
//        .create()
//        .withExpiresAt(expiresAt)
//        .sign(defaultConfig.algorithm)
//
//      val jwtVerifier = new JwtVerifier(defaultConfig)
//
//      val verified = jwtVerifier.verifyJwtNoClaims(token)
//
//      verified shouldBe
//        JwtVerifyError
//          .TokenExpired(s"The Token has expired on $expiresAt.")
//          .asLeft
//    }
  }
}
