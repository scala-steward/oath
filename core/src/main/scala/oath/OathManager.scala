package oath

import com.auth0.jwt.{JWT, JWTVerifier}
import oath.config.OathConfig
import oath.model.JWT

import java.time.Instant
import scala.jdk.CollectionConverters.MapHasAsJava
import scala.util.Try
import scala.util.chaining.scalaUtilChainingOps
import scala.util.control.Exception.allCatch

class OathManager(config: OathConfig) {

  private val jwtCreator  = JWT.create()
  private val jwtVerifier = createVerifier()

  jwtCreator.sign(config.jwt.jws.algorithm)

  private def createVerifier(): JWTVerifier =
    JWT
      .require(config.jwt.jws.algorithm)
      .withIssuer("issuer")
      .build()

  def issueJWT[H, P](jwtClaims: model.JWTClaims[H, P])(implicit
      headerEncoder: ClaimsEncoder[H],
      payloadEncoder: ClaimsEncoder[P]
  ): Try[model.JWT[H, P]] =
    allCatch.withTry(
      jwtCreator
        .tap(jwtCreator =>
          jwtClaims.header.map(jwtHeader => jwtCreator.withHeader(headerEncoder.encode(jwtHeader).asJava)))
        .tap(jwtCreator =>
          jwtClaims.payload.map(jwtPayload => jwtCreator.withPayload(payloadEncoder.encode(jwtPayload).asJava)))
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
      headerDecoder: ClaimsDecoder[H],
      payloadDecoder: ClaimsDecoder[P]
  ): Try[model.JWTClaims[H, P]] =
    jwtVerifier.verify(token)

}
