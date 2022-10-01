package oath.model

sealed trait VerifyJWTError

object VerifyJWTError {

  final case class FailedVerifyingJWT(error: String) extends VerifyJWTError

  final case class DecodingError(field: String, error: String) extends VerifyJWTError
}
