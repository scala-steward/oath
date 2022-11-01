package oath.model

import eu.timepit.refined.types.string.NonEmptyString

final case class Jwt[+C](claims: C, token: NonEmptyString)
