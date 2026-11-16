terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }
}

provider "aws" {
  region = var.region

  # Solo para el job "plan" del CI, que corre sin credenciales reales (TF_VAR_plan_sin_credenciales=true):
  # el proveedor no consulta STS ni el metadata service y el plan se calcula con -refresh=false.
  skip_credentials_validation = var.plan_sin_credenciales
  skip_requesting_account_id  = var.plan_sin_credenciales
  skip_metadata_api_check     = var.plan_sin_credenciales
  skip_region_validation      = var.plan_sin_credenciales

  default_tags {
    tags = { Project = var.project, ManagedBy = "terraform" }
  }
}
