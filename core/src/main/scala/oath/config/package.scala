package oath

import cats.implicits.catsSyntaxOptionId
import com.typesafe.config.{Config, ConfigException}

import scala.concurrent.duration.FiniteDuration
import scala.jdk.CollectionConverters.ListHasAsScala
import scala.jdk.DurationConverters.JavaDurationOps
import scala.util.control.Exception.allCatch

package object config {

  implicit class ConfigOps(private val config: Config) {

    private def ifMissingDefault[T](default: T): PartialFunction[Throwable, T] = { case ConfigException.Missing =>
      default
    }

    def getMaybeString(path: String): Option[String] =
      allCatch
        .withTry(config.getString(path))
        .map(_.some)
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

    def getSeqString(path: String): Seq[String] =
      allCatch
        .withTry(config.getStringList(path))
        .map(_.asScala.toSeq)
        .recover(ifMissingDefault(Seq.empty[String]))
        .get

  }
}
