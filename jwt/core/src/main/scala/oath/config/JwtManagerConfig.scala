package oath.config

import com.typesafe.config.{Config, ConfigFactory}

import scala.util.chaining.scalaUtilChainingOps

final case class JwtManagerConfig(issuer: IssuerConfig, verifier: VerifierConfig)

object JwtManagerConfig {

  def loadOrThrow(location: String): JwtManagerConfig = ConfigFactory.load().getConfig(location).pipe(loadOrThrow)

  def loadOrThrow(config: Config): JwtManagerConfig =
    JwtManagerConfig(IssuerConfig.loadOrThrow(config), VerifierConfig.loadOrThrow(config))

}
