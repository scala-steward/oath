package oath

import com.auth0.jwt.exceptions._
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.{JWT, JWTVerifier}
import oath.config.VerifierConfig
import oath.model.{JwtClaims, VerifyJwtError}

import scala.util.control.Exception.allCatch

import scala.util.chaining.scalaUtilChainingOps

class JwtVerifier(config: VerifierConfig, customJWTVerifier: Option[JWTVerifier] = None) {

  private val jwtVerifier =
    customJWTVerifier.getOrElse(
      JWT
        .require(config.algorithm)
        .tap(jwtVerification => config.providedWith.issuerClaim.map(jwtVerification.withIssuer))
        .tap(jwtVerification => config.providedWith.subjectClaim.map(jwtVerification.withSubject))
        .tap(jwtVerification => config.providedWith.audienceClaims.map(jwtVerification.withAudience(_)))
        .tap(jwtVerification => config.providedWith.presenceClaims.map(jwtVerification.withClaimPresence))
        .tap(jwtVerification => config.providedWith.nullClaims.map(jwtVerification.withNullClaim))
        .tap(jwtVerification =>
          config.leewayWindow.leeway.map(duration => jwtVerification.acceptLeeway(duration.toSeconds)))
        .tap(jwtVerification =>
          config.leewayWindow.issuedAt.map(duration => jwtVerification.acceptIssuedAt(duration.toSeconds)))
        .tap(jwtVerification =>
          config.leewayWindow.expiresAt.map(duration => jwtVerification.acceptExpiresAt(duration.toSeconds)))
        .tap(jwtVerification =>
          config.leewayWindow.notBefore.map(duration => jwtVerification.acceptNotBefore(duration.toSeconds)))
        .build()
    )

  private def handler(decodedJWT: => DecodedJWT): Either[VerifyJwtError, DecodedJWT] =
    allCatch
      .withTry(decodedJWT)
      .toEither
      .left
      .map {
        case e: IllegalArgumentException       => VerifyJwtError.IllegalArgument(e.getMessage)
        case e: AlgorithmMismatchException     => VerifyJwtError.AlgorithmMismatch(e.getMessage)
        case e: SignatureVerificationException => VerifyJwtError.SignatureVerificationError(e.getMessage)
        case e: TokenExpiredException          => VerifyJwtError.TokenExpired(e.getMessage)
        case e: JWTVerificationException       => VerifyJwtError.VerificationError(e.getMessage)
        case e: MissingClaimException          => VerifyJwtError.MissingClaim(e.getMessage)
        case e: IncorrectClaimException        => VerifyJwtError.IncorrectClaim(e.getMessage)
        case e                                 => VerifyJwtError.UnexpectedError(e.getMessage)
      }

  private def verify(token: String): Either[VerifyJwtError, DecodedJWT] =
    handler(
      jwtVerifier
        .verify(token)
    )

  def verifyJwt(token: String): Either[VerifyJwtError, JwtClaims.NoClaims.type] =
    verify(token).map(_ => JwtClaims.NoClaims)

  def verifyJwt[H, P](token: String)(implicit
      headerDecoder: ClaimsDecoder[H],
      payloadDecoder: ClaimsDecoder[P]
  ): Either[VerifyJwtError, JwtClaims.JwtClaimsHP[H, P]] =
    for {
      decodedJwt <- verify(token)
      header     <- headerDecoder.decode(decodedJwt)
      payload    <- payloadDecoder.decode(decodedJwt)
    } yield JwtClaims.JwtClaimsHP(header, payload)

  def verifyJwt[P](token: String)(implicit
      payloadDecoder: ClaimsDecoder[P]
  ): Either[VerifyJwtError, JwtClaims.JwtClaimsP[P]] =
    for {
      decodedJwt <- verify(token)
      payload    <- payloadDecoder.decode(decodedJwt)
    } yield JwtClaims.JwtClaimsP(payload)
}
