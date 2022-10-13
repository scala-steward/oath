package oath

import java.time.temporal.ChronoUnit
import java.time.{Clock, Instant}
import java.util.UUID

import com.auth0.jwt.exceptions.{JWTCreationException, SignatureGenerationException}
import com.auth0.jwt.{JWT, JWTCreator}
import oath.config.IssuerConfig
import oath.model.{IssueJwtError, Jwt, JwtClaims}

import scala.jdk.CollectionConverters._
import scala.util.control.Exception.allCatch

import scala.util.chaining.scalaUtilChainingOps

class JwtIssuer(config: IssuerConfig)(implicit clock: Clock = Clock.systemUTC()) {

  private val jwtBuilder: JWTCreator.Builder = JWT.create()

  private def setPredefinedClaims(builder: JWTCreator.Builder): JWTCreator.Builder =
    builder
      .tap(builder => config.registered.issuerClaim.map(builder.withIssuer))
      .tap(builder => config.registered.subjectClaim.map(builder.withSubject))
      .tap(builder => builder.withAudience(config.registered.audienceClaim: _*))
      .tap(builder =>
        if (config.registered.includeJwtIdClaim)
          config.registered.issuerClaim
            .map(_ + "-")
            .getOrElse("")
            .pipe(prefix => builder.withJWTId(prefix + UUID.randomUUID().toString)))
      .tap { builder =>
        val issuedAt  = Instant.now(clock).truncatedTo(ChronoUnit.MILLIS)
        val expiresAt = config.registered.expiresAtOffset.map(duration => issuedAt.plusMillis(duration.toMillis))
        val notBefore =
          config.registered.notBeforeOffset.map(duration => issuedAt.plusMillis(duration.toMillis))
        if (config.registered.includeIssueAtClaim) builder.withIssuedAt(issuedAt)
        expiresAt.map(builder.withExpiresAt)
        notBefore.map(builder.withNotBefore)
      }

  private def handler[T <: JwtClaims](jwt: => Jwt[T]): Either[IssueJwtError, Jwt[T]] =
    allCatch.withTry(jwt).toEither.left.map {
      case e: IllegalArgumentException     => IssueJwtError.IllegalArgument(e.getMessage)
      case e: JWTCreationException         => IssueJwtError.JwtCreationError(e.getMessage)
      case e: SignatureGenerationException => IssueJwtError.SignatureGenerationError(e.getMessage)
      case e                               => IssueJwtError.UnexpectedError(e.getMessage)
    }

  def issueJWT(): Either[IssueJwtError, Jwt[JwtClaims.NoClaims.type]] =
    handler(
      jwtBuilder
        .tap(setPredefinedClaims)
        .sign(config.algorithm)
        .pipe(Jwt(JwtClaims.NoClaims, _))
    )

  def issueJWT[H, P](jwtClaims: JwtClaims.JwtClaimsHP[H, P])(implicit
      headerClaimsEncoder: HeaderClaimsEncoder[H],
      payloadClaimsEncoder: PayloadClaimsEncoder[P]
  ): Either[IssueJwtError, Jwt[JwtClaims.JwtClaimsHP[H, P]]] =
    handler(
      jwtBuilder
        .tap(builder => headerClaimsEncoder.encode(jwtClaims.header).asJava.pipe(builder.withHeader))
        .tap(builder => payloadClaimsEncoder.encode(jwtClaims.payload).asJava.pipe(builder.withPayload))
        .tap(setPredefinedClaims)
        .sign(config.algorithm)
        .pipe(Jwt(jwtClaims, _))
    )

  def issueJWT[P](jwtClaims: JwtClaims.JwtClaimsP[P])(implicit
      payloadClaimsEncoder: PayloadClaimsEncoder[P]
  ): Either[IssueJwtError, Jwt[JwtClaims.JwtClaimsP[P]]] =
    handler(
      jwtBuilder
        .tap(builder => payloadClaimsEncoder.encode(jwtClaims.payload).asJava.pipe(builder.withPayload))
        .tap(setPredefinedClaims)
        .sign(config.algorithm)
        .pipe(Jwt(jwtClaims, _))
    )

  def issueJWT[H](jwtClaims: JwtClaims.JwtClaimsH[H])(implicit
      headerClaimsEncoder: HeaderClaimsEncoder[H]
  ): Either[IssueJwtError, Jwt[JwtClaims.JwtClaimsH[H]]] =
    handler(
      jwtBuilder
        .tap(builder => headerClaimsEncoder.encode(jwtClaims.header).asJava.pipe(builder.withHeader))
        .tap(setPredefinedClaims)
        .sign(config.algorithm)
        .pipe(Jwt(jwtClaims, _))
    )
}
