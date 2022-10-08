package oath

import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.{JWT => JavaJWT, JWTVerifier}
import oath.model.{Jwt, JwtClaims, VerifyJWTError}
import oath.old.TokenConfig

import java.time.Instant
import scala.jdk.CollectionConverters.MapHasAsJava
import scala.util.Try
import scala.util.chaining.scalaUtilChainingOps
import scala.util.control.Exception.allCatch

class JWTManager(config: TokenConfig, customJWTVerifier: Option[JWTVerifier] = None) {

  private val jwtCreator  = JavaJWT.create()
  private val jwtVerifier = createVerifier()

  private def createVerifier(): JWTVerifier =
    customJWTVerifier.getOrElse(
      JavaJWT
        .require(config.signature.verifyingAlgorithm)
        .tap(jwtVerification => config.verifier.withIssuer.map(jwtVerification.withIssuer))
        .tap(jwtVerification => config.verifier.withSubject.map(jwtVerification.withSubject))
        .tap(jwtVerification => config.verifier.withAudience.map(jwtVerification.withAudience(_)))
        .tap(jwtVerification =>
          config.verifier.acceptLeeway.map(duration => jwtVerification.acceptLeeway(duration.toSeconds)))
        .tap(jwtVerification =>
          config.verifier.acceptIssuedAt.map(duration => jwtVerification.acceptIssuedAt(duration.toSeconds)))
        .tap(jwtVerification =>
          config.verifier.acceptExpiresAt.map(duration => jwtVerification.acceptExpiresAt(duration.toSeconds)))
        .tap(jwtVerification =>
          config.verifier.acceptNotBefore.map(duration => jwtVerification.acceptNotBefore(duration.toSeconds)))
        .build()
    )

  def issueJWT[H, P](jwtClaims: JwtClaims.JwtClaimsHP[H, P])(implicit
                                                             headerEncoder: ClaimsEncoder[H],
                                                             payloadEncoder: ClaimsEncoder[P]
  ): Try[Jwt.JWTHPS[H, P]] =
    allCatch.withTry(
      jwtCreator
        .tap(jwtCreator => headerEncoder.encode(jwtClaims.header).asJava.pipe(jwtCreator.withHeader))
        .tap(jwtCreator => payloadEncoder.encode(jwtClaims.payload).asJava.pipe(jwtCreator.withPayload))
        .tap(jwtCreator => config.registeredClaims.issuer.map(jwtCreator.withIssuer))
        .tap(jwtCreator => config.registeredClaims.subject.map(jwtCreator.withSubject))
        .tap(jwtCreator => config.registeredClaims.audience.map(jwtCreator.withAudience(_)))
        .tap { jwtCreator =>
          val issuedAt  = Instant.now()
          val expiresAt = config.registeredClaims.expirationTime.map(duration => issuedAt.plusMillis(duration.toMillis))
          val notBefore =
            config.registeredClaims.notBeforeOffset.map(duration => issuedAt.plusMillis(duration.toMillis))
          if (config.registeredClaims.includeIssuedAt) jwtCreator.withIssuedAt(issuedAt)
          expiresAt.map(jwtCreator.withExpiresAt)
          notBefore.map(jwtCreator.withNotBefore)
        }
        .sign(config.signature.signingAlgorithm)
        .pipe(Jwt.JWTHPS(jwtClaims, _))
    )

  def issueJWT[P](jwtClaims: model.JwtClaims[Nothing, P])(implicit
                                                          maybePayloadDecoder: ClaimsEncoder[P]
  ): Try[model.Jwt[Nothing, P]] = issueJWT(jwtClaims)

  def verifyJWT(token: String): Either[VerifyJWTError.FailedVerifyingJWT, JwtClaims.NoClaims.type] =
    verifyToken(token).map(_ => JwtClaims.NoClaims)

  def verifyJWT[H, P](token: String)(implicit
      headerDecoder: ClaimsDecoder[H],
      payloadDecoder: ClaimsDecoder[P]
  ): Either[model.VerifyJWTError, JwtClaims.JwtClaimsHP[H, P]] =
    for {
      decodedJwt <- verifyToken(token)
      header     <- headerDecoder.decode(decodedJwt)
      payload    <- payloadDecoder.decode(decodedJwt)
    } yield JwtClaims.JwtClaimsHP(header, payload)

  def verifyJWT[P](token: String)(implicit
      payloadDecoder: ClaimsDecoder[P]
  ): Either[model.VerifyJWTError, JwtClaims.JwtClaimsP[P]] =
    for {
      decodedJwt <- verifyToken(token)
      payload    <- payloadDecoder.decode(decodedJwt)
    } yield JwtClaims.JwtClaimsP(payload)

  private def verifyToken(token: String): Either[VerifyJWTError.FailedVerifyingJWT, DecodedJWT] =
    allCatch
      .withTry(jwtVerifier.verify(token))
      .toEither
      .left
      .map(error => VerifyJWTError.FailedVerifyingJWT(error.getMessage))

}
