package oath

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import oath.NestedHeader._
import oath.NestedPayload._
import oath.config.IssuerConfig
import oath.model.{IssueJwtError, JwtClaims}
import oath.testkit.{AnyWordSpecBase, PropertyBasedTesting}
import oath.utils.ClockHelper

import scala.util.Try

import cats.implicits.catsSyntaxEitherId
import scala.concurrent.duration.DurationInt
import scala.jdk.CollectionConverters.ListHasAsScala
import scala.jdk.CollectionConverters.MapHasAsJava
import scala.util.chaining.scalaUtilChainingOps

class JwtIssuerSpec extends AnyWordSpecBase with PropertyBasedTesting with ClockHelper {

  "JwtIssuer" should {

    "issue jwt tokens" when {

      "issue token with predefine configure claims" in forAll { config: IssuerConfig =>
        val jwtIssuer   = new JwtIssuer(config, clock)
        val noClaimsJwt = jwtIssuer.issueJWT().value
        val verifier    = JWT.require(config.algorithm).acceptLeeway(1.minutes.toSeconds).build()

        Option(verifier.verify(noClaimsJwt.token).getIssuer) shouldBe config.registered.issuerClaim
        Option(verifier.verify(noClaimsJwt.token).getSubject) shouldBe config.registered.subjectClaim
        Option(verifier.verify(noClaimsJwt.token).getAudience).toSeq
          .flatMap(_.asScala) shouldBe config.registered.audienceClaims
        Try(verifier.verify(noClaimsJwt.token).getId).toOption
        Try(verifier.verify(noClaimsJwt.token).getIssuedAt.toInstant).toOption shouldBe Option.when(
          config.registered.includeIssueAtClaim)(now)
        Try(verifier.verify(noClaimsJwt.token).getExpiresAt.toInstant).toOption shouldBe
          Option.when(config.registered.expiresAtOffset.nonEmpty)(
            now.plusMillis(config.registered.expiresAtOffset.value.toMillis))
        Try(verifier.verify(noClaimsJwt.token).getNotBefore.toInstant).toOption shouldBe Option.when(
          config.registered.notBeforeOffset.nonEmpty)(now
          .plusMillis(config.registered.notBeforeOffset.value.toMillis))
      }

      "issue token with no additional claims" in forAll { config: IssuerConfig =>
        val jwtIssuer   = new JwtIssuer(config)
        val noClaimsJwt = jwtIssuer.issueJWT().value

        noClaimsJwt.token should not be empty
      }

      "issue token with header claims" in forAll { (config: IssuerConfig, header: NestedHeader) =>
        val jwtIssuer = new JwtIssuer(config)
        val jwt       = jwtIssuer.issueJWT(JwtClaims.JwtClaimsH(header)).value

        val headerResult = JWT
          .require(Algorithm.none())
          .build()
          .verify(jwt.token)
          .pipe(nestedHeaderDecoder.decode)
          .value

        headerResult shouldBe header
        jwt.token should not be empty
      }

      "issue token with payload claims" in forAll { (config: IssuerConfig, payload: NestedPayload) =>
        val jwtIssuer = new JwtIssuer(config)
        val jwt       = jwtIssuer.issueJWT(JwtClaims.JwtClaimsP(payload)).value

        val nestedPayloadResult = JWT
          .require(Algorithm.none())
          .build()
          .verify(jwt.token)
          .pipe(nestedPayloadDecoder.decode)
          .value

        nestedPayloadResult shouldBe payload
        jwt.token should not be empty
      }

      "issue token with header & payload claims" in forAll {
        (config: IssuerConfig, header: NestedHeader, payload: NestedPayload) =>
          val jwtIssuer = new JwtIssuer(config)
          val jwt       = jwtIssuer.issueJWT(JwtClaims.JwtClaimsHP(header, payload)).value

          val (headerResult, payloadResult) = JWT
            .require(Algorithm.none())
            .build()
            .verify(jwt.token)
            .pipe(decodedJwt =>
              (nestedHeaderDecoder.decode(decodedJwt).value, nestedPayloadDecoder.decode(decodedJwt).value))

          headerResult shouldBe header
          payloadResult shouldBe payload
          jwt.token should not be empty
      }

      "issue token should fail with IllegalArgument when algorithm is set to null" in forAll { config: IssuerConfig =>
        val jwtIssuer = new JwtIssuer(config.copy(algorithm = null))
        val jwt       = jwtIssuer.issueJWT()

        jwt shouldBe IssueJwtError.IllegalArgument("The Algorithm cannot be null.").asLeft
      }

      "issue token should fail with IllegalArgument when claim name is set to null" in forAll { config: IssuerConfig =>
        implicit val mapClaimsEncoder: ClaimsEncoder[java.util.Map[String, Object]] = identity(_)

        val jwtIssuer          = new JwtIssuer(config)
        val stringNull: String = null
        val nullKeyMap         = Map[String, Object](stringNull -> "value").asJava
        val jwt                = jwtIssuer.issueJWT(JwtClaims.JwtClaimsP(nullKeyMap))

        jwt shouldBe IssueJwtError.IllegalArgument("The Custom Claim's name can't be null.").asLeft
      }
    }
  }
}
