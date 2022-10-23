package oath.config

import com.auth0.jwt.algorithms.Algorithm
import com.typesafe.config.{Config, ConfigFactory}
import eu.timepit.refined.types.string.NonEmptyString
import oath.config.VerifierConfig._

import scala.concurrent.duration.FiniteDuration

final case class VerifierConfig(algorithm: Algorithm,
                                providedWith: ProvidedWithConfig,
                                leewayWindow: LeewayWindowConfig
)

object VerifierConfig {

  final case class ProvidedWithConfig(issuerClaim: Option[NonEmptyString],
                                      subjectClaim: Option[NonEmptyString],
                                      audienceClaims: Seq[NonEmptyString],
                                      presenceClaims: Seq[NonEmptyString],
                                      nullClaims: Seq[NonEmptyString]
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
    val issuerClaim    = providedWithScoped.getMaybeNonEmptyString("issuer-claim")
    val subjectClaim   = providedWithScoped.getMaybeNonEmptyString("subject-claim")
    val audienceClaim  = providedWithScoped.getSeqNonEmptyString("audience-claims")
    val presenceClaims = providedWithScoped.getSeqNonEmptyString("presence-claims")
    val nullClaims     = providedWithScoped.getSeqNonEmptyString("null-claims")
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
