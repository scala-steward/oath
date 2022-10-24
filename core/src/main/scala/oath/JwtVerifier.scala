package oath

import cats.syntax.all._
import com.auth0.jwt.exceptions._
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.{JWT, JWTVerifier}
import oath.config.VerifierConfig
import oath.model.{JwtClaims, JwtVerifyError}

import scala.util.control.Exception.allCatch

import cats.implicits.toTraverseOps
import scala.util.chaining.scalaUtilChainingOps

class JwtVerifier(config: VerifierConfig, customJWTVerifier: Option[JWTVerifier] = None) {

  private lazy val jwtVerifier =
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

  private def safeDecode[T](
      decodedObject: => Either[JwtVerifyError.DecodingError, T]
  ): Either[JwtVerifyError.DecodingError, T] =
    allCatch
      .withTry(decodedObject)
      .sequence
      .flatMap(maybeT => maybeT.toEither.left.map(error => JwtVerifyError.DecodingError(Nil, error.getMessage)))

  private def verify(token: String): Either[JwtVerifyError, DecodedJWT] =
    handler(
      jwtVerifier
        .verify(token)
    )

  def verifyJwtNoClaims(token: String): Either[JwtVerifyError, JwtClaims.NoClaims.type] =
    verify(token).map(_ => JwtClaims.NoClaims)

  def verifyJwt[H, P](token: String)(implicit
      headerDecoder: ClaimsDecoder[H],
      payloadDecoder: ClaimsDecoder[P]
  ): Either[JwtVerifyError, JwtClaims.JwtClaimsHP[H, P]] =
    verify(token).flatMap { decodedJwt =>
      (safeDecode(headerDecoder.decode(decodedJwt)).toValidatedNec,
       safeDecode(payloadDecoder.decode(decodedJwt)).toValidatedNec).mapN { case (header, payload) =>
        JwtClaims.JwtClaimsHP(header, payload)
      }.toEither.left
        .map(_.toList)
        .left
        .map(list => JwtVerifyError.DecodingErrors(list.headOption, list.tail.headOption))
    }

  def verifyJwtHeader[H](token: String)(implicit
      headerDecoder: ClaimsDecoder[H]
  ): Either[JwtVerifyError, JwtClaims.JwtClaimsH[H]] =
    for {
      decodedJwt <- verify(token)
      payload    <- safeDecode(headerDecoder.decode(decodedJwt))
    } yield JwtClaims.JwtClaimsH(payload)

  def verifyJwtPayload[P](token: String)(implicit
      payloadDecoder: ClaimsDecoder[P]
  ): Either[JwtVerifyError, JwtClaims.JwtClaimsP[P]] =
    for {
      decodedJwt <- verify(token)
      payload    <- safeDecode(payloadDecoder.decode(decodedJwt))
    } yield JwtClaims.JwtClaimsP(payload)
}
