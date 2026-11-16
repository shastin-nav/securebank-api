# SecureBank-Infra · stack AWS de SecureBank API (Sesión 11)
# Versión corregida: cada bloque indica el hallazgo de Checkov que cierra [CKV_...].
# Detalle de la remediación y Security Score antes/después: infra/README.md

locals {
  tags = { Project = var.project, Owner = "securepipeline", ManagedBy = "terraform" }
  azs  = ["${var.region}a", "${var.region}b"]
}

# =====================================================================
# Cifrado: una CMK para todo el stack [CKV_AWS_7 · CKV2_AWS_64]
# =====================================================================
resource "aws_kms_key" "kms_key" {
  description             = "CMK de SecureBank (S3, RDS, EBS, DynamoDB, ECR, logs, SNS, SQS)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AdministracionDeLaCuenta"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "ServiciosAWSDelStack"
        Effect    = "Allow"
        Principal = { Service = ["cloudtrail.amazonaws.com", "logs.${var.region}.amazonaws.com", "sns.amazonaws.com", "s3.amazonaws.com"] }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:Encrypt", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
      },
    ]
  })
  tags = local.tags
}

# =====================================================================
# Red
# =====================================================================
resource "aws_vpc" "vpc_main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${var.project}-vpc" })
}

# El SG por defecto de la VPC no permite nada [CKV2_AWS_12]
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.vpc_main.id
  tags   = local.tags
}

# Subredes públicas: solo para el ALB (2 AZ). Nada recibe IP pública automática [CKV_AWS_130]
resource "aws_subnet" "subnet_pub" {
  count                   = 2
  vpc_id                  = aws_vpc.vpc_main.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.project}-pub-${count.index}" })
}

# Subredes privadas: EC2, RDS y Lambda
resource "aws_subnet" "subnet_priv" {
  count             = 2
  vpc_id            = aws_vpc.vpc_main.id
  cidr_block        = "10.0.${count.index + 11}.0/24"
  availability_zone = local.azs[count.index]
  tags              = merge(local.tags, { Name = "${var.project}-priv-${count.index}" })
}

# Flow logs de la VPC a CloudWatch cifrado [CKV2_AWS_11]
resource "aws_flow_log" "flow_logs" {
  vpc_id          = aws_vpc.vpc_main.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
  tags            = local.tags
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/securebank/vpc-flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.kms_key.arn
  tags              = local.tags
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.project}-flow-logs"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "escribir-flow-logs"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

# ---------------- security groups (todas las reglas con descripción) [CKV_AWS_23] ----------------
# ALB: solo HTTPS desde Internet; el 80 se usa únicamente para redirigir a 443.
# Ya no hay SSH abierto [CKV_AWS_24] ni salida irrestricta [CKV_AWS_382].
resource "aws_security_group" "sg_public" {
  name        = "${var.project}-alb"
  description = "ALB publico de SecureBank: HTTPS de entrada, solo hacia la app"
  vpc_id      = aws_vpc.vpc_main.id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.sg_public.id
  description       = "HTTPS publico hacia el ALB"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "alb_a_app" {
  security_group_id            = aws_security_group.sg_public.id
  description                  = "ALB hacia la API en el puerto de la app"
  referenced_security_group_id = aws_security_group.sg_app.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
}

resource "aws_security_group" "sg_app" {
  name        = "${var.project}-app"
  description = "Instancias de SecureBank API: solo trafico desde el ALB y SSH desde la VPN"
  vpc_id      = aws_vpc.vpc_main.id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "app_desde_alb" {
  security_group_id            = aws_security_group.sg_app.id
  description                  = "Trafico HTTP de la app solo desde el ALB"
  referenced_security_group_id = aws_security_group.sg_public.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
}

resource "aws_vpc_security_group_ingress_rule" "app_ssh_vpn" {
  security_group_id = aws_security_group.sg_app.id
  description       = "SSH administrativo solo desde la red interna / VPN"
  cidr_ipv4         = var.admin_cidr
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}

resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.sg_app.id
  description       = "Salida HTTPS (APIs de AWS y actualizaciones)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "app_a_db" {
  security_group_id            = aws_security_group.sg_app.id
  description                  = "API hacia PostgreSQL"
  referenced_security_group_id = aws_security_group.sg_db.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

# BD: solo accesible desde la app, nunca desde Internet
resource "aws_security_group" "sg_db" {
  name        = "${var.project}-db"
  description = "PostgreSQL de SecureBank: solo desde las instancias de la app"
  vpc_id      = aws_vpc.vpc_main.id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "db_desde_app" {
  security_group_id            = aws_security_group.sg_db.id
  description                  = "PostgreSQL solo desde el SG de la app"
  referenced_security_group_id = aws_security_group.sg_app.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

# =====================================================================
# Cómputo: subred privada, sin IP pública, IMDSv2, discos cifrados con la CMK
# [CKV_AWS_88 · CKV_AWS_79 · CKV_AWS_8 · CKV_AWS_135 · CKV_AWS_126 · CKV2_AWS_41]
# =====================================================================
resource "aws_instance" "ec2_web" {
  ami                         = var.ami_id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.subnet_priv[0].id
  vpc_security_group_ids      = [aws_security_group.sg_app.id]
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.app.name
  ebs_optimized               = true
  monitoring                  = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted  = true
    kms_key_id = aws_kms_key.kms_key.arn
  }

  tags = merge(local.tags, { Name = "${var.project}-web" })
}

resource "aws_instance" "ec2_worker" {
  ami                         = var.ami_id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.subnet_priv[1].id
  vpc_security_group_ids      = [aws_security_group.sg_app.id]
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.app.name # ya no el perfil admin
  ebs_optimized               = true
  monitoring                  = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted  = true
    kms_key_id = aws_kms_key.kms_key.arn
  }

  tags = merge(local.tags, { Name = "${var.project}-worker" })
}

# [CKV_AWS_3 · CKV_AWS_189]
resource "aws_ebs_volume" "ebs_volume" {
  availability_zone = local.azs[0]
  size              = 20
  encrypted         = true
  kms_key_id        = aws_kms_key.kms_key.arn
  tags              = local.tags
}

# =====================================================================
# Almacenamiento S3: privado, versionado, cifrado con KMS, con logging y ciclo de vida
# [CKV_AWS_20 · CKV2_AWS_6 · CKV_AWS_21 · CKV_AWS_145 · CKV_AWS_18 · CKV2_AWS_61 · CKV2_AWS_62]
# =====================================================================
resource "aws_s3_bucket" "s3_backups" {
  bucket = "${var.project}-backups"
  tags   = local.tags
}

resource "aws_s3_bucket" "s3_logs" {
  #checkov:skip=CKV_AWS_18:Es el bucket de destino de los access logs; loguearse a sí mismo genera un bucle
  #checkov:skip=CKV_AWS_144:Replicación entre regiones fuera del alcance del ramo (costo); queda en el backlog
  bucket = "${var.project}-logs"
  tags   = local.tags
}

locals {
  buckets = {
    backups = aws_s3_bucket.s3_backups.id
    logs    = aws_s3_bucket.s3_logs.id
  }
}

# Sin ACL: el dueño del bucket controla todo, las ACL públicas dejan de existir [CKV_AWS_20]
resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = local.buckets
  bucket   = each.value
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "s3_backups" {
  bucket                  = aws_s3_bucket.s3_backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "s3_logs" {
  bucket                  = aws_s3_bucket.s3_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "s3_backups" {
  bucket = aws_s3_bucket.s3_backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "s3_logs" {
  bucket = aws_s3_bucket.s3_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_backups" {
  bucket = aws_s3_bucket.s3_backups.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.kms_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_logs" {
  bucket = aws_s3_bucket.s3_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.kms_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "s3_backups" {
  bucket        = aws_s3_bucket.s3_backups.id
  target_bucket = aws_s3_bucket.s3_logs.id
  target_prefix = "s3-access/backups/"
}

resource "aws_s3_bucket_lifecycle_configuration" "s3_backups" {
  bucket = aws_s3_bucket.s3_backups.id
  rule {
    id     = "respaldos-a-glacier"
    status = "Enabled"
    filter {}
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "s3_logs" {
  bucket = aws_s3_bucket.s3_logs.id
  rule {
    id     = "retencion-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 400
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_notification" "s3_backups" {
  bucket = aws_s3_bucket.s3_backups.id
  topic {
    topic_arn = aws_sns_topic.alertas.arn
    events    = ["s3:ObjectRemoved:*"]
  }
}

resource "aws_s3_bucket_notification" "s3_logs" {
  bucket = aws_s3_bucket.s3_logs.id
  topic {
    topic_arn = aws_sns_topic.alertas.arn
    events    = ["s3:ObjectRemoved:*"]
  }
}

# Solo CloudTrail y el ALB pueden escribir en el bucket de logs; todo por TLS
resource "aws_s3_bucket_policy" "s3_logs" {
  bucket = aws_s3_bucket.s3_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "SoloTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.s3_logs.arn, "${aws_s3_bucket.s3_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.s3_logs.arn
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.s3_logs.arn}/cloudtrail/AWSLogs/${var.account_id}/*"
      },
      {
        Sid       = "AlbAccessLogs"
        Effect    = "Allow"
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.s3_logs.arn}/alb/AWSLogs/${var.account_id}/*"
      },
    ]
  })
}

# =====================================================================
# Base de datos: privada, cifrada, con respaldos y logs
# [CKV_AWS_17 · CKV_AWS_16 · CKV_AWS_133 · CKV_AWS_293 · CKV_AWS_157 · CKV_AWS_353 · CKV_AWS_118
#  CKV_AWS_226 · CKV_AWS_129 · CKV_AWS_161 · CKV2_AWS_60 · CKV2_AWS_30]
# =====================================================================
resource "aws_db_subnet_group" "db" {
  name       = "${var.project}-db"
  subnet_ids = aws_subnet.subnet_priv[*].id
  tags       = local.tags
}

resource "aws_db_parameter_group" "postgres" {
  name   = "${var.project}-postgres16"
  family = "postgres16"

  parameter {
    name  = "log_statement"
    value = "ddl"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }
  tags = local.tags
}

resource "aws_db_instance" "rds_postgres" {
  identifier                            = "${var.project}-db"
  engine                                = "postgres"
  engine_version                        = "16.4"
  instance_class                        = "db.t3.micro"
  allocated_storage                     = 20
  username                              = var.db_username
  manage_master_user_password           = true # la contraseña vive en Secrets Manager, nunca en el código
  db_subnet_group_name                  = aws_db_subnet_group.db.name
  parameter_group_name                  = aws_db_parameter_group.postgres.name
  vpc_security_group_ids                = [aws_security_group.sg_db.id]
  publicly_accessible                   = false
  storage_encrypted                     = true
  kms_key_id                            = aws_kms_key.kms_key.arn
  backup_retention_period               = 7
  deletion_protection                   = true
  skip_final_snapshot                   = false
  final_snapshot_identifier             = "${var.project}-db-final"
  copy_tags_to_snapshot                 = true
  multi_az                              = true
  auto_minor_version_upgrade            = true
  iam_database_authentication_enabled   = true
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.kms_key.arn
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  performance_insights_retention_period = 7
  tags                                  = local.tags
}

resource "aws_iam_role" "rds_monitoring" {
  name = "${var.project}-rds-monitoring"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "monitoring.rds.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# [CKV_AWS_119 · CKV_AWS_28]
resource "aws_dynamodb_table" "dynamodb_txn" {
  name         = "${var.project}-transacciones"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.kms_key.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  deletion_protection_enabled = true
  tags                        = local.tags
}

# [CKV_AWS_51 · CKV_AWS_163 · CKV_AWS_136] tags inmutables: :v1 no se puede reemplazar (Sesión 13)
resource "aws_ecr_repository" "ecr_repo" {
  name                 = var.project
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.kms_key.arn
  }
  tags = local.tags
}

# =====================================================================
# Identidad: mínimo privilegio, sin usuarios IAM con llaves estáticas
# [CKV_AWS_62 · CKV_AWS_63 · CKV_AWS_355 · CKV_AWS_286-290 · CKV2_AWS_40 · CKV_AWS_273 · CKV_AWS_40]
# =====================================================================
resource "aws_iam_role" "iam_role_app" {
  name = "${var.project}-app"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

# La app solo lee y escribe respaldos en SU bucket (antes: Action "*" sobre Resource "*")
resource "aws_iam_role_policy" "app" {
  name = "securebank-app-minimo-privilegio"
  role = aws_iam_role.iam_role_app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RespaldosDeLaApp"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["${aws_s3_bucket.s3_backups.arn}/app/*"]
      },
      {
        Sid      = "TransaccionesDynamo"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"]
        Resource = [aws_dynamodb_table.dynamodb_txn.arn]
      },
      {
        Sid      = "UsarLaCMK"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.kms_key.arn]
      },
    ]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project}-app"
  role = aws_iam_role.iam_role_app.name
}

# CI: el usuario IAM con llaves de larga duración se reemplaza por un rol asumido con OIDC de
# GitHub Actions, acotado a este repositorio y a la rama main.
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
  tags            = local.tags
}

resource "aws_iam_role" "iam_role_ci" {
  name = "${var.project}-ci"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:ref:refs/heads/main"
        }
      }
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "ci" {
  name = "publicar-imagen-ecr"
  role = aws_iam_role.iam_role_ci.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PublicarEnElRepoDeSecureBank"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage",
        ]
        Resource = [aws_ecr_repository.ecr_repo.arn]
      },
      {
        # GetAuthorizationToken no admite recurso específico (limitación de la API de ECR)
        Sid      = "LoginEcr"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = ["*"]
      },
    ]
  })
}

# =====================================================================
# Exposición: ALB con HTTPS, TLS 1.2+, WAF, logs y redirección 80 → 443
# [CKV_AWS_2 · CKV_AWS_103 · CKV2_AWS_20 · CKV_AWS_131 · CKV_AWS_150 · CKV_AWS_91 · CKV2_AWS_28]
# =====================================================================
resource "aws_lb" "alb_public" {
  name                       = "${var.project}-alb"
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.sg_public.id]
  subnets                    = aws_subnet.subnet_pub[*].id
  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.s3_logs.id
    prefix  = "alb"
    enabled = true
  }
  tags = local.tags
}

resource "aws_lb_target_group" "api" {
  name        = "${var.project}-api"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc_main.id
  target_type = "instance"

  health_check {
    path    = "/health"
    matcher = "200"
  }
  tags = local.tags
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.alb_public.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "http" {
  #checkov:skip=CKV_AWS_2:Listener HTTP que solo redirige a HTTPS (301); no sirve contenido
  #checkov:skip=CKV_AWS_103:No negocia TLS: solo redirige a HTTPS (301)
  load_balancer_arn = aws_lb.alb_public.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_wafv2_web_acl" "alb" {
  name  = "${var.project}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-common"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit-login"
    priority = 3
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 300
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-waf"
    sampled_requests_enabled   = true
  }
  tags = local.tags
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.alb_public.arn
  web_acl_arn  = aws_wafv2_web_acl.alb.arn
}

resource "aws_cloudwatch_log_group" "waf" {
  # WAF exige que el nombre del log group empiece con aws-waf-logs-
  name              = "aws-waf-logs-${var.project}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.kms_key.arn
  tags              = local.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "alb" {
  resource_arn            = aws_wafv2_web_acl.alb.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}

# ---------------- Lambda: en VPC, con DLQ, concurrencia, trazas y firma de código ----------------
# [CKV_AWS_117 · CKV_AWS_116 · CKV_AWS_115 · CKV_AWS_50 · CKV_AWS_272]
data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/.build/lambda.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${var.project}-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "lambda_dlq" {
  name = "enviar-a-dlq"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = [aws_sqs_queue.lambda_dlq.arn] },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = [aws_kms_key.kms_key.arn] },
    ]
  })
}

resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${var.project}-lambda-dlq"
  kms_master_key_id         = aws_kms_key.kms_key.arn
  message_retention_seconds = 1209600
  tags                      = local.tags
}

resource "aws_signer_signing_profile" "lambda" {
  platform_id = "AWSLambda-SHA384-ECDSA"
  name_prefix = "securebank"
  tags        = local.tags
}

resource "aws_lambda_code_signing_config" "lambda" {
  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda.version_arn]
  }
  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }
}

resource "aws_security_group" "sg_lambda" {
  name        = "${var.project}-lambda"
  description = "Lambda de SecureBank: solo salida HTTPS"
  vpc_id      = aws_vpc.vpc_main.id
  tags        = local.tags
}

resource "aws_vpc_security_group_egress_rule" "lambda_https" {
  security_group_id = aws_security_group.sg_lambda.id
  description       = "Salida HTTPS hacia APIs de AWS"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_lambda_function" "lambda_api" {
  function_name                  = "${var.project}-api"
  role                           = aws_iam_role.lambda.arn
  runtime                        = "python3.12"
  handler                        = "handler.handler"
  filename                       = data.archive_file.lambda.output_path
  source_code_hash               = data.archive_file.lambda.output_base64sha256
  reserved_concurrent_executions = 20
  code_signing_config_arn        = aws_lambda_code_signing_config.lambda.arn

  vpc_config {
    subnet_ids         = aws_subnet.subnet_priv[*].id
    security_group_ids = [aws_security_group.sg_lambda.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }
  tags = local.tags
}

# =====================================================================
# Trazabilidad: CloudTrail multirregión, cifrado, con validación, CloudWatch y SNS
# [CKV_AWS_251 · CKV_AWS_67 · CKV_AWS_36 · CKV_AWS_35 · CKV_AWS_252 · CKV2_AWS_10]
# =====================================================================
resource "aws_sns_topic" "alertas" {
  name              = "${var.project}-alertas-seguridad"
  kms_master_key_id = aws_kms_key.kms_key.arn
  tags              = local.tags
}

# S3 y CloudTrail solo pueden publicar en el tópico desde esta cuenta
resource "aws_sns_topic_policy" "alertas" {
  arn = aws_sns_topic.alertas.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicarDesdeS3YCloudTrail"
      Effect    = "Allow"
      Principal = { Service = ["s3.amazonaws.com", "cloudtrail.amazonaws.com"] }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alertas.arn
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
    }]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/securebank/cloudtrail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.kms_key.arn
  tags              = local.tags
}

resource "aws_iam_role" "cloudtrail" {
  name = "${var.project}-cloudtrail"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "cloudtrail" {
  name = "escribir-en-cloudwatch"
  role = aws_iam_role.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "cloudtrail" {
  name                          = "${var.project}-trail"
  s3_bucket_name                = aws_s3_bucket.s3_logs.id
  s3_key_prefix                 = "cloudtrail"
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.kms_key.arn
  sns_topic_name                = aws_sns_topic.alertas.name
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail.arn
  tags                          = local.tags

  depends_on = [aws_s3_bucket_policy.s3_logs]
}
