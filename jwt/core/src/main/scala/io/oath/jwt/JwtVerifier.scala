package io.oath.jwt

import cats.syntax.all._
import com.auth0.jwt.JWT
import com.auth0.jwt.exceptions._
import com.auth0.jwt.interfaces.DecodedJWT
import io.oath.jwt.config.JwtVerifierConfig
import io.oath.jwt.model.{JwtClaims, JwtToken, JwtVerifyError, RegisteredClaims}
import io.oath.jwt.utils._

import scala.util.control.Exception.allCatch

import scala.util.chaining.scalaUtilChainingOps

final class JwtVerifier(config: JwtVerifierConfig) {

  private lazy val jwtVerifier =
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
        config.leewayWindow.leeway.map(duration => jwtVerification.acceptLeeway(duration.toSeconds)))
      .tap(jwtVerification =>
        config.leewayWindow.issuedAt.map(duration => jwtVerification.acceptIssuedAt(duration.toSeconds)))
      .tap(jwtVerification =>
        config.leewayWindow.expiresAt.map(duration => jwtVerification.acceptExpiresAt(duration.toSeconds)))
      .tap(jwtVerification =>
        config.leewayWindow.notBefore.map(duration => jwtVerification.acceptNotBefore(duration.toSeconds)))
      .build()

  private def getRegisteredClaims(decodedJWT: DecodedJWT): RegisteredClaims =
    RegisteredClaims(
      iss = decodedJWT.getOptionNonEmptyStringIssuer,
      sub = decodedJWT.getOptionNonEmptyStringSubject,
      aud = decodedJWT.getSeqNonEmptyStringAudience,
      exp = decodedJWT.getOptionExpiresAt,
      nbf = decodedJWT.getOptionNotBefore,
      iat = decodedJWT.getOptionIssueAt,
      jti = decodedJWT.getOptionNonEmptyStringID
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
      .fold(error => JwtVerifyError.DecodingError(error.getMessage, error).asLeft, identity)

  private def verify(jwt: JwtToken): Either[JwtVerifyError, DecodedJWT] =
    handler(
      jwtVerifier
        .verify(jwt.token.value)
    )

  def verifyJwt(jwt: JwtToken.Token): Either[JwtVerifyError, JwtClaims.Claims] =
    verify(jwt).map(getRegisteredClaims).map(JwtClaims.Claims)

  def verifyJwt[H](jwt: JwtToken.TokenH)(implicit
      claimsDecoder: ClaimsDecoder[H]
  ): Either[JwtVerifyError, JwtClaims.ClaimsH[H]] =
    for {
      decodedJwt <- verify(jwt)
      json       <- base64DecodeToken(decodedJwt.getHeader)
      payload    <- safeDecode(claimsDecoder.decode(json))
      registeredClaims = getRegisteredClaims(decodedJwt)
    } yield JwtClaims.ClaimsH(payload, registeredClaims)

  def verifyJwt[P](jwt: JwtToken.TokenP)(implicit
      claimsDecoder: ClaimsDecoder[P]
  ): Either[JwtVerifyError, JwtClaims.ClaimsP[P]] =
    for {
      decodedJwt <- verify(jwt)
      json       <- base64DecodeToken(decodedJwt.getPayload)
      payload    <- safeDecode(claimsDecoder.decode(json))
      registeredClaims = getRegisteredClaims(decodedJwt)
    } yield JwtClaims.ClaimsP(payload, registeredClaims)

  def verifyJwt[H, P](jwt: JwtToken.TokenHP)(implicit
      headerDecoder: ClaimsDecoder[H],
      payloadDecoder: ClaimsDecoder[P]
  ): Either[JwtVerifyError, JwtClaims.ClaimsHP[H, P]] =
    verify(jwt).flatMap { decodedJwt =>
      for {
        jsonHeader  <- base64DecodeToken(decodedJwt.getHeader)
        jsonPayload <- base64DecodeToken(decodedJwt.getPayload)
        jwtClaims <- safeDecode(headerDecoder.decode(jsonHeader)) match {
          case Right(header) =>
            safeDecode(payloadDecoder.decode(jsonPayload)).left
              .map(payloadDecodingError => JwtVerifyError.DecodingErrors(None, payloadDecodingError.some))
              .map { payload =>
                val registeredClaims = getRegisteredClaims(decodedJwt)
                JwtClaims.ClaimsHP(header, payload, registeredClaims)
              }
          case Left(headerDecodingError) =>
            safeDecode(payloadDecoder.decode(jsonPayload)).left.toOption
              .pipe(JwtVerifyError.DecodingErrors(headerDecodingError.some, _))
              .asLeft
        }
      } yield jwtClaims
    }
}
