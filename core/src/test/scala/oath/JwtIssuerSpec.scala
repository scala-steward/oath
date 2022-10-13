package oath

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.circe.{Encoder, Json, JsonObject}
import oath.config.IssuerConfig
import oath.model.JwtClaims.JwtClaimsP
import oath.testkit.{AnyWordSpecBase, PropertyBasedTesting}
import org.scalactic.anyvals.PosInt

import java.time.temporal.ChronoUnit
import java.time.{Clock, Instant, ZoneId}
import java.util.Base64
import scala.concurrent.duration.DurationInt
import scala.jdk.CollectionConverters.{ListHasAsScala, MapHasAsJava, SeqHasAsJava}
import scala.util.Try
import scala.util.chaining.scalaUtilChainingOps
import io.circe.generic.auto._
import io.circe.parser.decode
import io.circe.syntax.EncoderOps
import oath.model.VerifyJwtError
import oath.model.VerifyJwtError.DecodingError

import java.nio.charset.StandardCharsets

class JwtIssuerSpec extends AnyWordSpecBase with PropertyBasedTesting {

  implicit override val generatorDrivenConfig: PropertyCheckConfiguration = PropertyCheckConfiguration(PosInt(1))

  val now            = Instant.now().truncatedTo(ChronoUnit.SECONDS)
  implicit val clock = Clock.fixed(now, ZoneId.of("UTC"))

  final case class SimplePayload(name: String, data: List[String])
  final case class NestedPayload(name: String, mapping: Map[String, SimplePayload])

  implicit val nestedPayloadEncoder: PayloadClaimsEncoder[NestedPayload] = nestedPayload => {
    implicitly[Encoder[NestedPayload]].asJson.fold()
    Json.fromJsonObject(Map(""->""))
    Map(
      "name" -> nestedPayload.name,
      "mapping" -> nestedPayload.mapping.view
        .mapValues(value => Map("name" -> value.name, "data" -> value.data.asJava).asJava)
        .toMap
        .asJava
    )
  }

  implicit val nestedPayloadDecoder: ClaimsDecoder[NestedPayload] = decodedToken =>
    decode[NestedPayload](decodedToken).left.map(e => VerifyJwtError.JwtDecodingError(e.getMessage))

  "JwtIssuer" should {

    "issue jwt tokens" when {

      "issue token with predefine configure claims" in forAll { config: IssuerConfig =>
        val jwtIssuer   = new JwtIssuer(config)(clock)
        val noClaimsJwt = jwtIssuer.issueJWT().value
        val verifier    = JWT.require(config.algorithm).acceptLeeway(1.minutes.toSeconds).build()

        Option(verifier.verify(noClaimsJwt.token).getIssuer) shouldBe config.registered.issuerClaim
        Option(verifier.verify(noClaimsJwt.token).getSubject) shouldBe config.registered.subjectClaim
        Option(verifier.verify(noClaimsJwt.token).getAudience).toSeq
          .flatMap(_.asScala) shouldBe config.registered.audienceClaim
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

      "issue token with additional payload claims" in forAll { config: IssuerConfig =>
        val jwtIssuer   = new JwtIssuer(config)
        val nested      = NestedPayload("name", Map("1" -> SimplePayload("pay", List("1", "2"))))
        val noClaimsJwt = jwtIssuer.issueJWT(JwtClaimsP(nested)).value

        println(noClaimsJwt.token)

        println(
          JWT
            .require(Algorithm.none())
            .build()
            .verify(noClaimsJwt.token)
            .getPayload
            .pipe(Base64.getDecoder.decode)
            .pipe(new String(_, StandardCharsets.UTF_8))
            .pipe(nestedPayloadDecoder.decode))

        noClaimsJwt.token should not be empty
      }
    }
  }
}
