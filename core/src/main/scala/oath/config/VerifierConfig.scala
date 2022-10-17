package oath.config

import com.auth0.jwt.algorithms.Algorithm
import com.typesafe.config.{Config, ConfigFactory}
import oath.config.VerifierConfig._

import scala.concurrent.duration.FiniteDuration

final case class VerifierConfig(algorithm: Algorithm,
                                providedWith: ProvidedWithConfig,
                                leewayWindow: LeewayWindowConfig
)

object VerifierConfig {

  final case class ProvidedWithConfig(issuerClaim: Option[String],
                                      subjectClaim: Option[String],
                                      audienceClaims: Seq[String],
                                      presenceClaims: Seq[String],
                                      nullClaims: Seq[String]
  )

  final case class LeewayWindowConfig(leeway: Option[FiniteDuration],
                                      issuedAt: Option[FiniteDuration],
                                      expiresAt: Option[FiniteDuration],
                                      notBefore: Option[FiniteDuration]
  )

  private val VerifierConfigObject     = "issuer"
  private val AlgorithmConfigObject    = "algorithm"
  private val ProvidedWithConfigObject = "provided-with"
  private val LeewayWindowConfigObject = "leeway-window"

  private def loadProvidedWithConfigOrThrow(providedWithScoped: Config): ProvidedWithConfig = {
    val issuerClaim    = providedWithScoped.getMaybeString("issuer-claim")
    val subjectClaim   = providedWithScoped.getMaybeString("subject-claim")
    val audienceClaim  = providedWithScoped.getSeqString("audience-claims")
    val presenceClaims = providedWithScoped.getSeqString("presence-claims")
    val nullClaims     = providedWithScoped.getSeqString("null-claims")
    ProvidedWithConfig(issuerClaim, subjectClaim, audienceClaim, presenceClaims, nullClaims)
  }

  private def loadLeewayWindowConfigOrThrow(leewayWindowScoped: Config): LeewayWindowConfig = {
    val leeway    = leewayWindowScoped.getMaybeFiniteDuration("leeway")
    val issuedAt  = leewayWindowScoped.getMaybeFiniteDuration("issued-at")
    val expiresAt = leewayWindowScoped.getMaybeFiniteDuration("expires-at")
    val notBefore = leewayWindowScoped.getMaybeFiniteDuration("not-before")
    LeewayWindowConfig(leeway, issuedAt, expiresAt, notBefore)
  }

  def loadOrThrow(config: Config = ConfigFactory.load()): VerifierConfig = {
    val verifierScoped = config.getConfig(VerifierConfigObject)
    val algorithm    = AlgorithmLoader.loadAlgorithmOrThrow(config.getConfig(AlgorithmConfigObject), forIssuing = false)
    val providedWith = loadProvidedWithConfigOrThrow(verifierScoped.getConfig(ProvidedWithConfigObject))
    val leewayWindow = loadLeewayWindowConfigOrThrow(verifierScoped.getConfig(LeewayWindowConfigObject))

    VerifierConfig(algorithm, providedWith, leewayWindow)
  }
}
