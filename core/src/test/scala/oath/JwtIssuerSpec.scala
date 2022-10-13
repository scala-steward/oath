package oath

import java.time.temporal.ChronoUnit
import java.time.{Clock, Instant, ZoneId}

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import oath.NestedHeader._
import oath.NestedPayload._
import oath.config.IssuerConfig
import oath.model.JwtClaims
import oath.testkit.{AnyWordSpecBase, PropertyBasedTesting}
import org.scalactic.anyvals.PosInt

import scala.util.Try

import scala.concurrent.duration.DurationInt
import scala.jdk.CollectionConverters.ListHasAsScala
import scala.util.chaining.scalaUtilChainingOps

class JwtIssuerSpec extends AnyWordSpecBase with PropertyBasedTesting {

  implicit override val generatorDrivenConfig: PropertyCheckConfiguration = PropertyCheckConfiguration(PosInt(1))

  val now            = Instant.now().truncatedTo(ChronoUnit.SECONDS)
  implicit val clock = Clock.fixed(now, ZoneId.of("UTC"))

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
    }
  }
}
