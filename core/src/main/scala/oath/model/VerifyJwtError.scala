package oath.model

sealed trait VerifyJwtError {
  def error: String
}

object VerifyJwtError {

  final case class IllegalArgument(error: String) extends VerifyJwtError

  final case class AlgorithmMismatch(error: String) extends VerifyJwtError

  final case class IncorrectClaim(error: String) extends VerifyJwtError

  final case class JwtDecodingError(error: String) extends VerifyJwtError

  final case class DecodingError(fields: Seq[String], error: String) extends VerifyJwtError

  final case class VerificationError(error: String) extends VerifyJwtError

  final case class MissingClaim(error: String) extends VerifyJwtError

  final case class SignatureVerificationError(error: String) extends VerifyJwtError

  final case class TokenExpired(error: String) extends VerifyJwtError

  final case class UnexpectedError(error: String) extends VerifyJwtError
}
