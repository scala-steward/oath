package oath

import com.typesafe.config.{Config, ConfigException}
import eu.timepit.refined.types.string.NonEmptyString

import scala.concurrent.duration.FiniteDuration
import scala.util.control.Exception.allCatch

import cats.implicits.catsSyntaxOptionId
import scala.jdk.CollectionConverters.ListHasAsScala
import scala.jdk.DurationConverters.JavaDurationOps

package object config {

  implicit class ConfigOps(private val config: Config) {

    private def ifMissingDefault[T](default: T): PartialFunction[Throwable, T] = { case _: ConfigException.Missing =>
      default
    }

    def getMaybeNonEmptyString(path: String): Option[NonEmptyString] =
      allCatch
        .withTry(config.getString(path))
        .map(_.some)
        .map(_.map(NonEmptyString.unsafeFrom))
        .recover(ifMissingDefault(None))
        .get

    def getMaybeFiniteDuration(path: String): Option[FiniteDuration] =
      allCatch
        .withTry(config.getDuration(path))
        .map(_.toScala.some)
        .recover(ifMissingDefault(None))
        .get

    def getBooleanDefaultFalse(path: String): Boolean =
      allCatch
        .withTry(config.getBoolean(path))
        .recover(ifMissingDefault(false))
        .get

    def getSeqNonEmptyString(path: String): Seq[NonEmptyString] =
      allCatch
        .withTry(config.getStringList(path))
        .map(_.asScala.toSeq)
        .map(_.map(NonEmptyString.unsafeFrom))
        .recover(ifMissingDefault(Seq.empty[NonEmptyString]))
        .get

  }
}
