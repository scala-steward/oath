package oath

import java.time.temporal.ChronoUnit
import java.time.{Clock, Instant}
import java.util.UUID

import com.auth0.jwt.exceptions.JWTCreationException
import com.auth0.jwt.{JWT, JWTCreator}
import eu.timepit.refined.types.string.NonEmptyString
import oath.config.IssuerConfig
import oath.model._

import scala.util.control.Exception.allCatch

import scala.jdk.CollectionConverters.MapHasAsJava
import scala.util.chaining.scalaUtilChainingOps

class JwtIssuer(config: IssuerConfig, clock: Clock = Clock.systemUTC()) {

  private val jwtBuilder: JWTCreator.Builder = JWT.create()

  private def setPredefinedClaims(builder: JWTCreator.Builder, registeredClaims: RegisteredClaims): JWTCreator.Builder =
    builder
      .tap(builder => registeredClaims.iss.map(nonEmptyString => builder.withIssuer(nonEmptyString.value)))
      .tap(builder => registeredClaims.sub.map(nonEmptyString => builder.withSubject(nonEmptyString.value)))
      .tap(builder => builder.withAudience(registeredClaims.aud.map(_.value).toArray: _*))
      .tap(builder => registeredClaims.jti.map(nonEmptyString => builder.withJWTId(nonEmptyString.value)))
      .tap(builder => registeredClaims.iat.map(builder.withIssuedAt))
      .tap(builder => registeredClaims.exp.map(builder.withExpiresAt))
      .tap(builder => registeredClaims.nbf.map(builder.withNotBefore))

  private def setRegisteredClaims(adHocRegisteredClaims: RegisteredClaims): RegisteredClaims = {
    val now = Instant.now(clock).truncatedTo(ChronoUnit.MILLIS)
    RegisteredClaims(
      iss = adHocRegisteredClaims.iss orElse config.registered.issuerClaim,
      sub = adHocRegisteredClaims.sub orElse config.registered.subjectClaim,
      aud = if (adHocRegisteredClaims.aud.isEmpty) config.registered.audienceClaims else adHocRegisteredClaims.aud,
      exp = adHocRegisteredClaims.exp orElse config.registered.expiresAtOffset.map(duration =>
        now.plusMillis(duration.toMillis)),
      nbf = adHocRegisteredClaims.nbf orElse config.registered.notBeforeOffset.map(duration =>
        now.plusMillis(duration.toMillis)),
      iat = adHocRegisteredClaims.iat orElse Option.when(config.registered.includeIssueAtClaim)(now),
      jti = adHocRegisteredClaims.jti orElse Option
        .when(config.registered.includeJwtIdClaim)(
          config.registered.issuerClaim
            .map(_.value + "-")
            .getOrElse("")
            .pipe(prefix => prefix + UUID.randomUUID().toString))
        .flatMap(NonEmptyString.unapply)
    )
  }

  private def handler[T](jwt: => Jwt[T]): Either[IssueJwtError, Jwt[T]] =
    allCatch.withTry(jwt).toEither.left.map {
      case e: IllegalArgumentException => IssueJwtError.IllegalArgument(e.getMessage)
      case e: JWTCreationException     => IssueJwtError.JwtCreationError(e.getMessage)
      case e                           => IssueJwtError.UnexpectedError(e.getMessage)
    }

  def issueJwt(
      claims: Claims = Claims()
  ): Either[IssueJwtError, Jwt[Claims]] =
    handler(
      jwtBuilder
        .pipe(_ -> setRegisteredClaims(claims.registered))
        .pipe { case (builder, registeredClaims) =>
          setPredefinedClaims(builder, registeredClaims).sign(config.algorithm) -> registeredClaims
        }
        .pipe { case (token, registeredClaims) =>
          Jwt(Claims(registeredClaims), NonEmptyString.unsafeFrom(token))
        }
    )

  def issueJwt[H](claims: ClaimsH[H])(implicit
      claimsEncoder: ClaimsEncoder[H]
  ): Either[IssueJwtError, Jwt[ClaimsH[H]]] =
    handler(
      jwtBuilder
        .tap(builder =>
          claimsEncoder
            .encode(claims.header)
            .pipe(json =>
              builder.withHeader(Map(dataField -> json).asJava.asInstanceOf[java.util.Map[String, Object]])))
        .pipe(_ -> setRegisteredClaims(claims.registered))
        .pipe { case (builder, registeredClaims) =>
          setPredefinedClaims(builder, registeredClaims).sign(config.algorithm) -> registeredClaims
        }
        .pipe { case (token, registeredClaims) =>
          Jwt(claims.copy(registered = registeredClaims), NonEmptyString.unsafeFrom(token))
        }
    )

  def issueJwt[P](claims: ClaimsP[P])(implicit
      claimsEncoder: ClaimsEncoder[P]
  ): Either[IssueJwtError, Jwt[ClaimsP[P]]] =
    handler(
      jwtBuilder
        .tap(builder =>
          claimsEncoder
            .encode(claims.payload)
            .pipe(json => builder.withPayload(Map(dataField -> json).asJava)))
        .pipe(_ -> setRegisteredClaims(claims.registered))
        .pipe { case (builder, registeredClaims) =>
          setPredefinedClaims(builder, registeredClaims).sign(config.algorithm) -> registeredClaims
        }
        .pipe { case (token, registeredClaims) =>
          Jwt(claims.copy(registered = registeredClaims), NonEmptyString.unsafeFrom(token))
        }
    )

  def issueJwt[H, P](claims: ClaimsHP[H, P])(implicit
      headerClaimsEncoder: ClaimsEncoder[H],
      payloadClaimsEncoder: ClaimsEncoder[P]
  ): Either[IssueJwtError, Jwt[ClaimsHP[H, P]]] =
    handler(
      jwtBuilder
        .tap(builder =>
          headerClaimsEncoder
            .encode(claims.header)
            .pipe(json =>
              builder.withHeader(Map(dataField -> json).asJava.asInstanceOf[java.util.Map[String, Object]])))
        .tap(builder =>
          payloadClaimsEncoder
            .encode(claims.payload)
            .pipe(json => builder.withPayload(Map(dataField -> json).asJava)))
        .pipe(_ -> setRegisteredClaims(claims.registered))
        .pipe { case (builder, registeredClaims) =>
          setPredefinedClaims(builder, registeredClaims).sign(config.algorithm) -> registeredClaims
        }
        .pipe { case (token, registeredClaims) =>
          Jwt(claims.copy(registered = registeredClaims), NonEmptyString.unsafeFrom(token))
        }
    )
}
