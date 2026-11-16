output "alb_dns_name" {
  description = "DNS público del balanceador"
  value       = aws_lb.alb_public.dns_name
}

output "ecr_repository_url" {
  description = "Repositorio de imágenes de SecureBank"
  value       = aws_ecr_repository.ecr_repo.repository_url
}
