package oath

import cats.syntax.all._
import com.auth0.jwt.exceptions._
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.{JWT, JWTVerifier}
import oath.config.VerifierConfig
import oath.model._
import oath.syntax._

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

  private def getRegisteredClaims(decodedJWT: DecodedJWT): RegisteredClaims =
    RegisteredClaims(
      iss = decodedJWT.getClaim("iss").asOptionNonEmptyString,
      sub = decodedJWT.getClaim("sub").asOptionNonEmptyString,
      aud = decodedJWT.getClaim("aud").asSeqNonEmptyString,
      exp = decodedJWT.getClaim("exp").asOptionInstant,
      nbf = decodedJWT.getClaim("nbf").asOptionInstant,
      iat = decodedJWT.getClaim("iat").asOptionInstant,
      jti = decodedJWT.getClaim("jti").asOptionNonEmptyString
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
      .flatMap(maybeT => maybeT.toEither.left.map(error => JwtVerifyError.DecodingError(error.getMessage, error)))

  private def verify(jwt: JwtToken): Either[JwtVerifyError, DecodedJWT] =
    handler(
      jwtVerifier
        .verify(jwt.token.value)
    )

  def verifyJwt(jwt: JwtToken.Token): Either[JwtVerifyError, Claims] =
    verify(jwt).map(getRegisteredClaims).map(Claims)

  def verifyJwt[H](jwt: JwtToken.TokenH)(implicit
      claimsDecoder: ClaimsDecoder[H]
  ): Either[JwtVerifyError, ClaimsH[H]] =
    for {
      decodedJwt <- verify(jwt)
      payload    <- safeDecode(claimsDecoder.decode(decodedJwt.getHeaderClaim(dataField).asString()))
      registeredClaims = getRegisteredClaims(decodedJwt)
    } yield ClaimsH(payload, registeredClaims)

  def verifyJwt[P](jwt: JwtToken.TokenP)(implicit
      claimsDecoder: ClaimsDecoder[P]
  ): Either[JwtVerifyError, ClaimsP[P]] =
    for {
      decodedJwt <- verify(jwt)
      payload    <- safeDecode(claimsDecoder.decode(decodedJwt.getClaim(dataField).asString()))
      registeredClaims = getRegisteredClaims(decodedJwt)
    } yield ClaimsP(payload, registeredClaims)

  def verifyJwt[H, P](jwt: JwtToken.TokenHP)(implicit
      headerDecoder: ClaimsDecoder[H],
      payloadDecoder: ClaimsDecoder[P]
  ): Either[JwtVerifyError, ClaimsHP[H, P]] =
    verify(jwt).flatMap { decodedJwt =>
      safeDecode(headerDecoder.decode(decodedJwt.getClaim(dataField).asString())) match {
        case Right(header) =>
          safeDecode(payloadDecoder.decode(decodedJwt.getClaim(dataField).asString())).left
            .map(payloadDecodingError => JwtVerifyError.DecodingErrors(None, payloadDecodingError.some))
            .map { payload =>
              val registeredClaims = getRegisteredClaims(decodedJwt)
              ClaimsHP(header, payload, registeredClaims)
            }
        case Left(headerDecodingError) =>
          safeDecode(payloadDecoder.decode(decodedJwt.getClaim(dataField).asString())).left.toOption
            .pipe(JwtVerifyError.DecodingErrors(headerDecodingError.some, _))
            .asLeft
      }
    }
}
