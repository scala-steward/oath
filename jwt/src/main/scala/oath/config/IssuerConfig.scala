package oath.config

import com.auth0.jwt.algorithms.Algorithm
import com.typesafe.config.{Config, ConfigFactory}
import eu.timepit.refined.types.string.NonEmptyString
import oath.config.IssuerConfig.RegisteredConfig

import scala.concurrent.duration.FiniteDuration

final case class IssuerConfig(algorithm: Algorithm, registered: RegisteredConfig)

object IssuerConfig {

  final case class RegisteredConfig(issuerClaim: Option[NonEmptyString],
                                    subjectClaim: Option[NonEmptyString],
                                    audienceClaims: Seq[NonEmptyString],
                                    includeJwtIdClaim: Boolean,
                                    includeIssueAtClaim: Boolean,
                                    expiresAtOffset: Option[FiniteDuration],
                                    notBeforeOffset: Option[FiniteDuration]
  )

  private val IssuerConfigObject     = "issuer"
  private val AlgorithmConfigObject  = "algorithm"
  private val RegisteredConfigObject = "registered"

  private def loadRegisterScoped(registeredScoped: Config): RegisteredConfig = {
    val issuerClaim          = registeredScoped.getMaybeNonEmptyString("issuer-claim")
    val subjectClaim         = registeredScoped.getMaybeNonEmptyString("subject-claim")
    val audienceClaim        = registeredScoped.getSeqNonEmptyString("audience-claims")
    val includeIssuedAtClaim = registeredScoped.getBooleanDefaultFalse("include-issued-at-claim")
    val includeJwtIdClaim    = registeredScoped.getBooleanDefaultFalse("include-jwt-id-claim")
    val expiresAtOffset      = registeredScoped.getMaybeFiniteDuration("expires-at-offset")
    val notBeforeOffset      = registeredScoped.getMaybeFiniteDuration("not-before-offset")
    RegisteredConfig(
      issuerClaim,
      subjectClaim,
      audienceClaim,
      includeJwtIdClaim,
      includeIssuedAtClaim,
      expiresAtOffset,
      notBeforeOffset
    )
  }

  def loadOrThrow(config: Config = ConfigFactory.load()): IssuerConfig = {
    val issuerScoped = config.getConfig(IssuerConfigObject)
    val algorithm    = AlgorithmLoader.loadAlgorithmOrThrow(config.getConfig(AlgorithmConfigObject), forIssuing = true)
    val registered   = loadRegisterScoped(issuerScoped.getConfig(RegisteredConfigObject))

    IssuerConfig(algorithm, registered)
  }
}
