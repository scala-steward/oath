package oath.config

import com.auth0.jwt.algorithms.Algorithm
import oath.config.OathConfig.JWTConfig

import scala.concurrent.duration.FiniteDuration

final case class OathConfig(jwt: JWTConfig)

object OathConfig {

  final case class JWTConfig(jws: JWSConfig, payload: PayloadConfig)

  final case class JWSConfig(algorithm: Algorithm)

  final case class PayloadConfig(issuer: Option[String],
                                 subject: Option[String],
                                 audience: Option[String],
                                 expirationTime: Option[FiniteDuration],
                                 notBeforeOffset: Option[FiniteDuration],
                                 includeIssuedAt: Boolean,
                                 includeJwtId: Boolean
  )
}
