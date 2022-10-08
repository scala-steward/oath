package oath

import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.{JWT, JWTVerifier}
import oath.model.{JwtClaims, VerifyJWTError}
import oath.old.TokenConfig

import scala.util.chaining.scalaUtilChainingOps
import scala.util.control.Exception.allCatch

class JwtVerifier(config: TokenConfig, customJWTVerifier: Option[JWTVerifier] = None) {

  private val tokenVerifier = createVerifier()

  private def createVerifier(): JWTVerifier =
    customJWTVerifier.getOrElse(
      JWT
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

  def verifyToken(token: String): Either[VerifyJWTError, JwtClaims.NoClaims.type] =
    validateToken(token).map(_ => JwtClaims.NoClaims)

  def verifyToken[H, P](token: String)(implicit
      headerDecoder: ClaimsDecoder[H],
      payloadDecoder: ClaimsDecoder[P]
  ): Either[VerifyJWTError, JwtClaims.JwtClaimsHP[H, P]] =
    for {
      decodedJwt <- validateToken(token)
      header     <- headerDecoder.decode(decodedJwt)
      payload    <- payloadDecoder.decode(decodedJwt)
    } yield JwtClaims.JwtClaimsHP(header, payload)

  def verifyToken[P](token: String)(implicit
      payloadDecoder: ClaimsDecoder[P]
  ): Either[VerifyJWTError, JwtClaims.JwtClaimsP[P]] =
    for {
      decodedJwt <- validateToken(token)
      payload    <- payloadDecoder.decode(decodedJwt)
    } yield JwtClaims.JwtClaimsP(payload)

  private def validateToken(token: String): Either[VerifyJWTError, DecodedJWT] =
    allCatch
      .withTry(tokenVerifier.verify(token))
      .toEither
      .left
      .map(error => VerifyJWTError.FailedVerifyingJWT(error.getMessage))

}
