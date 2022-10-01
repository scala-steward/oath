package oath

import java.time.Instant
import java.util

import com.auth0.jwt.{JWT, JWTVerifier}
import oath.config.OathConfig

import scala.util.Try
import scala.util.control.Exception.allCatch

import scala.jdk.CollectionConverters.MapHasAsJava
import scala.util.chaining.scalaUtilChainingOps

class TokenManager(config: OathConfig, customJWTVerifier: Option[JWTVerifier] = None) {

  private val jwtCreator  = JWT.create()
  private val jwtVerifier = createVerifier()

  private def createVerifier(): JWTVerifier =
    customJWTVerifier.getOrElse(
      JWT
        .require(config.jwt.jws.algorithm)
        .tap(jwtVerification => config.jwt.verifier.withIssuer.map(jwtVerification.withIssuer))
        .tap(jwtVerification => config.jwt.verifier.withSubject.map(jwtVerification.withSubject))
        .tap(jwtVerification => config.jwt.verifier.withAudience.map(jwtVerification.withAudience(_)))
        .tap(jwtVerification =>
          config.jwt.verifier.acceptLeeway.map(duration => jwtVerification.acceptLeeway(duration.toSeconds)))
        .tap(jwtVerification =>
          config.jwt.verifier.acceptIssuedAt.map(duration => jwtVerification.acceptIssuedAt(duration.toSeconds)))
        .tap(jwtVerification =>
          config.jwt.verifier.acceptExpiresAt.map(duration => jwtVerification.acceptExpiresAt(duration.toSeconds)))
        .tap(jwtVerification =>
          config.jwt.verifier.acceptNotBefore.map(duration => jwtVerification.acceptNotBefore(duration.toSeconds)))
        .build()
    )

  private def extractJWTClaims[T](
      maybeClaims: Option[T]
  )(implicit encoder: ClaimsEncoder[T]): Option[util.Map[String, Any]] =
    maybeClaims.map(claims => encoder.encode(claims).asJava)

  def issueJWT[H, P](jwtClaims: model.TokenClaims[H, P])(implicit
                                                         maybeHeaderDecoder: ClaimsEncoder[H],
                                                         maybePayloadDecoder: ClaimsEncoder[P]
  ): Try[model.Token[H, P]] =
    allCatch.withTry(
      jwtCreator
        .tap(jwtCreator => extractJWTClaims(jwtClaims.header).map(jwtCreator.withHeader))
        .tap(jwtCreator => extractJWTClaims(jwtClaims.payload).map(jwtCreator.withPayload))
        .tap(jwtCreator => config.jwt.payload.issuer.map(jwtCreator.withIssuer))
        .tap(jwtCreator => config.jwt.payload.subject.map(jwtCreator.withSubject))
        .tap(jwtCreator => config.jwt.payload.audience.map(jwtCreator.withAudience(_)))
        .tap { jwtCreator =>
          val issuedAt  = Instant.now()
          val expiresAt = config.jwt.payload.expirationTime.map(duration => issuedAt.plusMillis(duration.toMillis))
          val notBefore = config.jwt.payload.notBeforeOffset.map(duration => issuedAt.plusMillis(duration.toMillis))
          if (config.jwt.payload.includeIssuedAt) jwtCreator.withIssuedAt(issuedAt)
          expiresAt.map(jwtCreator.withExpiresAt)
          notBefore.map(jwtCreator.withNotBefore)
        }
        .sign(config.jwt.jws.algorithm)
        .pipe(model.Token(jwtClaims.header, jwtClaims.payload, _))
    )

  def verifyJWT[H, P](token: String)(implicit
      maybeHeaderDecoder: ClaimsDecoder[H],
      maybePayloadDecoder: ClaimsDecoder[P]
  ): Either[model.VerifyJWTError, model.TokenClaims[H, P]] = {
    val decodedJwt = jwtVerifier.verify(token)
    for {
      header  <- maybeHeaderDecoder.decode(decodedJwt)
      payload <- maybePayloadDecoder.decode(decodedJwt)
    } yield model.TokenClaims(Option(header), Option(payload))
  }
}
