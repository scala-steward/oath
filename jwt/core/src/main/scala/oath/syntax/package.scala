package oath

import java.time.Instant

import com.auth0.jwt.interfaces.Claim
import eu.timepit.refined.types.string.NonEmptyString

import scala.util.Try

import cats.implicits.toTraverseOps
import scala.jdk.CollectionConverters.CollectionHasAsScala

package object syntax {

  private[oath] implicit class ClaimOps(private val claim: Claim) {
    def asOptionNonEmptyString: Option[NonEmptyString] =
      Option(claim.asString())
        .flatMap(NonEmptyString.unapply)

    def asOptionInstant: Option[Instant] = Option(claim.asInstant())

    def asSeqNonEmptyString: Seq[NonEmptyString] =
      Try(claim.asList(classOf[String]).asScala.toSeq).toOption.sequence.flatMap(_.flatMap(NonEmptyString.unapply))
  }
}
