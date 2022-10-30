package oath

import java.time.Instant
import java.util.Date
import java.{lang, util}
import com.auth0.jwt.interfaces.{Claim, DecodedJWT}
import eu.timepit.refined.types.string.NonEmptyString

import scala.jdk.CollectionConverters.CollectionHasAsScala

package object syntax {

  private[oath] implicit class ClaimOps(private val claim: Claim) {
    def asOptionNonEmptyString: Option[NonEmptyString] =
      Option(claim.asString())
        .flatMap(NonEmptyString.unapply)

    def asOptionInstant: Option[Instant] = Option(claim.asInstant())

    def asSeq: Seq[NonEmptyString] = claim.asList(classOf[String]).asScala.toSeq.flatMap(NonEmptyString.unapply)
  }

  private[oath] implicit class DecodedJWTOps(private val decodedJwt: DecodedJWT) {

  }
}
