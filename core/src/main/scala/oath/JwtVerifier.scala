package oath

import com.auth0.jwt.exceptions._
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.{JWT, JWTVerifier}
import oath.config.VerifierConfig
import oath.model.{JwtClaims, JwtVerifyError}

import scala.util.control.Exception.allCatch

import scala.util.chaining.scalaUtilChainingOps

class JwtVerifier(config: VerifierConfig, customJWTVerifier: Option[JWTVerifier] = None) {

  private val jwtVerifier =
    customJWTVerifier.getOrElse(
      JWT
        .require(config.algorithm)
        .tap(jwtVerification =>
          config.providedWith.issuerClaim.map(nonEmptyString => jwtVerification.withIssuer(nonEmptyString.value)))
        .tap(jwtVerification =>
          config.providedWith.subjectClaim.map(nonEmptyString => jwtVerification.withSubject(nonEmptyString.value)))
        .tap(jwtVerification =>
          if (config.providedWith.audienceClaims.nonEmpty)
            jwtVerification.withAudience(config.providedWith.audienceClaims.map(_.value).toArray: _*))
        .tap(jwtVerification =>
          config.providedWith.presenceClaims.map(nonEmptyString =>
            jwtVerification.withClaimPresence(nonEmptyString.value)))
        .tap(jwtVerification =>
          config.providedWith.nullClaims.map(nonEmptyString => jwtVerification.withNullClaim(nonEmptyString.value)))
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

  private def handler(decodedJWT: => DecodedJWT): Either[JwtVerifyError, DecodedJWT] =
    allCatch
      .withTry(decodedJWT)
      .toEither
      .left
      .map {
        case e: IllegalArgumentException       => JwtVerifyError.IllegalArgument(e.getMessage)
        case e: AlgorithmMismatchException     => JwtVerifyError.AlgorithmMismatch(e.getMessage)
        case e: SignatureVerificationException => JwtVerifyError.SignatureVerificationError(e.getMessage)
        case e: TokenExpiredException          => JwtVerifyError.TokenExpired(e.getMessage)
        case e: JWTVerificationException       => JwtVerifyError.VerificationError(e.getMessage)
        case e                                 => JwtVerifyError.UnexpectedError(e.getMessage)
      }

  private def verify(token: String): Either[JwtVerifyError, DecodedJWT] =
    handler(
      jwtVerifier
        .verify(token)
    )

  def verifyNoClaimsJwt(token: String): Either[JwtVerifyError, JwtClaims.NoClaims.type] =
    verify(token).map(_ => JwtClaims.NoClaims)

  def verifyJwt[H, P](token: String)(implicit
      headerDecoder: ClaimsDecoder[H],
      payloadDecoder: ClaimsDecoder[P]
  ): Either[JwtVerifyError, JwtClaims.JwtClaimsHP[H, P]] =
    for {
      decodedJwt <- verify(token)
      header     <- headerDecoder.decode(decodedJwt)
      payload    <- payloadDecoder.decode(decodedJwt)
    } yield JwtClaims.JwtClaimsHP(header, payload)

  def verifyJwt[P](token: String)(implicit
      payloadDecoder: ClaimsDecoder[P]
  ): Either[JwtVerifyError, JwtClaims.JwtClaimsP[P]] =
    for {
      decodedJwt <- verify(token)
      payload    <- payloadDecoder.decode(decodedJwt)
    } yield JwtClaims.JwtClaimsP(payload)
}
