package oath

import cats.implicits.toTraverseOps
import com.auth0.jwt.{JWT, JWTVerifier}
import oath.config.OathConfig
import oath.model.{DecodeError, JWT, JWTClaims}

import java.time.Instant
import java.util
import scala.jdk.CollectionConverters.MapHasAsJava
import scala.util.Try
import scala.util.chaining.scalaUtilChainingOps
import scala.util.control.Exception.allCatch

class OathManager(config: OathConfig, customJWTVerifier: Option[JWTVerifier] = None) {

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
  )(implicit maybeEncoder: Option[ClaimsEncoder[T]]): Option[util.Map[String, AnyRef]] = for {
    claims  <- maybeClaims
    encoder <- maybeEncoder
  } yield encoder.encode(claims).asJava

  def issueJWT[H, P](jwtClaims: model.JWTClaims[H, P])(implicit
      maybeHeaderDecoder: Option[ClaimsEncoder[H]],
      maybePayloadDecoder: Option[ClaimsEncoder[P]]
  ): Try[model.JWT[H, P]] =
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
        .pipe(JWT(jwtClaims.header, jwtClaims.payload, _))
    )

  def verifyJWT[H, P](token: String)(implicit
      maybeHeaderDecoder: Option[ClaimsDecoder[H]],
      maybePayloadDecoder: Option[ClaimsDecoder[P]]
  ): Either[DecodeError, model.JWTClaims[H, P]] = {
    val decodedJwt = jwtVerifier.verify(token)
    for {
      header  <- maybeHeaderDecoder.traverse(decoder => decoder.decode(decodedJwt))
      payload <- maybePayloadDecoder.traverse(decoder => decoder.decode(decodedJwt))
    } yield JWTClaims(header, payload)
  }

}
