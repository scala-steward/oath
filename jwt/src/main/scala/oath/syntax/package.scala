package oath

import java.time.Instant
import java.util.Date
import java.{lang, util}

import com.auth0.jwt.interfaces.Claim

package object syntax {

  implicit class ClaimOps(private val claim: Claim) {
    def asOptionString: Option[String] = Option(claim.asString())

    def asOptionBoolean: Option[lang.Boolean] = Option(claim.asBoolean())

    def asOptionDouble: Option[lang.Double] = Option(claim.asDouble())

    def asOptionInt: Option[Integer] = Option(claim.asInt())

    def asOptionLong: Option[lang.Long] = Option(claim.asLong())

    def asOptionDate: Option[Date] = Option(claim.asDate())

    def asOptionInstant: Option[Instant] = Option(claim.asInstant())

    def asOptionList[T >: Nothing](clazz: Class[T]): Option[util.List[T]] = Option(claim.asList(clazz))

    def asOptionMap: Option[util.Map[String, AnyRef]] = Option(claim.asMap())
  }

}
