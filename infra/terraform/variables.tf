variable "region" {
  description = "Región AWS del stack de SecureBank"
  type        = string
  default     = "sa-east-1"
}

variable "project" {
  description = "Prefijo de nombres de recursos"
  type        = string
  default     = "securebank"
}

variable "account_id" {
  description = "ID de la cuenta AWS (sin data source: el plan del CI no consulta la API)"
  type        = string
  default     = "000000000000"
}

variable "db_username" {
  description = "Usuario administrador de RDS"
  type        = string
  default     = "securebank_admin"
}

variable "ami_id" {
  description = "AMI de las instancias EC2"
  type        = string
  default     = "ami-0c55b159cbfafe1f0"
}
