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

variable "admin_cidr" {
  description = "Red interna / VPN desde la que se permite SSH administrativo"
  type        = string
  default     = "10.0.0.0/16"
}

variable "acm_certificate_arn" {
  description = "Certificado TLS del ALB (ACM)"
  type        = string
  default     = "arn:aws:acm:sa-east-1:000000000000:certificate/securebank-placeholder"
}

variable "github_repo" {
  description = "Repositorio autorizado a asumir el rol de CI por OIDC (owner/repo)"
  type        = string
  default     = "shastin-nav/securebank-api"
}

variable "plan_sin_credenciales" {
  description = "true solo en el CI: permite terraform plan sin credenciales de AWS"
  type        = bool
  default     = false
}
