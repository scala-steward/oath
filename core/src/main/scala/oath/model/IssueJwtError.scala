package oath.model

sealed trait IssueJwtError {
  def error: String
}

object IssueJwtError {

  final case class IllegalArgument(error: String) extends IssueJwtError

  final case class JwtCreationError(error: String) extends IssueJwtError

  final case class SignatureGenerationError(error: String) extends IssueJwtError

  final case class UnexpectedError(error: String) extends IssueJwtError
}
