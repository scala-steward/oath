package oath.config

import com.auth0.jwt.algorithms.Algorithm
import oath.config.OathConfig.JWTConfig

import scala.concurrent.duration.FiniteDuration

final case class OathConfig(jwt: JWTConfig)

object OathConfig {

  final case class JWTConfig(jws: JWSConfig, payload: PayloadConfig, verifier: VerifierConfig)

  final case class JWSConfig(algorithm: Algorithm = Algorithm.none())

  final case class PayloadConfig(issuer: Option[String] = None,
                                 subject: Option[String] = None,
                                 audience: Option[String] = None,
                                 expirationTime: Option[FiniteDuration] = None,
                                 notBeforeOffset: Option[FiniteDuration] = None,
                                 includeIssuedAt: Boolean = false,
                                 includeJwtId: Boolean = false
  )

  final case class VerifierConfig(withIssuer: Option[String] = None,
                                  withSubject: Option[String] = None,
                                  withAudience: Option[String] = None,
                                  acceptLeeway: Option[FiniteDuration] = None,
                                  acceptIssuedAt: Option[FiniteDuration] = None,
                                  acceptExpiresAt: Option[FiniteDuration] = None,
                                  acceptNotBefore: Option[FiniteDuration] = None
  )
}
