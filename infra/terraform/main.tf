# SecureBank-Infra · stack AWS de SecureBank API (Sesión 11)
# ⚠️ Versión inicial: contiene los 6 anti-patrones de la sesión, para medir el Security Score de partida.

# ---------------- red ----------------
resource "aws_vpc" "vpc_main" {
  cidr_block = "10.0.0.0/16"
  tags       = { Name = "${var.project}-vpc" }
}

resource "aws_subnet" "subnet_pub" {
  vpc_id                  = aws_vpc.vpc_main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "subnet_priv" {
  vpc_id     = aws_vpc.vpc_main.id
  cidr_block = "10.0.2.0/24"
}

# Anti-patrón: SSH y todo el tráfico abiertos a Internet
resource "aws_security_group" "sg_public" {
  name   = "${var.project}-public"
  vpc_id = aws_vpc.vpc_main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Anti-patrón: base de datos expuesta
resource "aws_security_group" "sg_db" {
  name   = "${var.project}-db"
  vpc_id = aws_vpc.vpc_main.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------- cómputo ----------------
resource "aws_instance" "ec2_web" {
  ami                         = var.ami_id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.subnet_pub.id
  vpc_security_group_ids      = [aws_security_group.sg_public.id]
  associate_public_ip_address = true
}

resource "aws_instance" "ec2_worker" {
  ami                    = var.ami_id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.subnet_pub.id
  vpc_security_group_ids = [aws_security_group.sg_public.id]
  iam_instance_profile   = aws_iam_instance_profile.admin.name
}

resource "aws_ebs_volume" "ebs_volume" {
  availability_zone = "${var.region}a"
  size              = 20
}

# ---------------- almacenamiento ----------------
# Anti-patrón: bucket de respaldos público
resource "aws_s3_bucket" "s3_backups" {
  bucket = "${var.project}-backups"
}

resource "aws_s3_bucket_acl" "s3_backups" {
  bucket = aws_s3_bucket.s3_backups.id
  acl    = "public-read"
}

resource "aws_s3_bucket" "s3_logs" {
  bucket = "${var.project}-logs"
}

# Anti-patrón: BD pública y sin cifrado en reposo
resource "aws_db_instance" "rds_postgres" {
  identifier                  = "${var.project}-db"
  engine                      = "postgres"
  engine_version              = "16.4"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = var.db_username
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.db.name
  vpc_security_group_ids      = [aws_security_group.sg_db.id]
  publicly_accessible         = true
  storage_encrypted           = false
  backup_retention_period     = 0
  skip_final_snapshot         = true
}

resource "aws_db_subnet_group" "db" {
  name       = "${var.project}-db"
  subnet_ids = [aws_subnet.subnet_pub.id, aws_subnet.subnet_priv.id]
}

resource "aws_dynamodb_table" "dynamodb_txn" {
  name         = "${var.project}-transacciones"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_kms_key" "kms_key" {
  description = "Clave de SecureBank"
}

resource "aws_ecr_repository" "ecr_repo" {
  name                 = var.project
  image_tag_mutability = "MUTABLE"
}

# ---------------- identidad ----------------
# Anti-patrón: IAM con comodines
resource "aws_iam_role" "iam_role_admin" {
  name = "${var.project}-admin"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "admin" {
  name = "admin"
  role = aws_iam_role.iam_role_admin.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_instance_profile" "admin" {
  name = "${var.project}-admin"
  role = aws_iam_role.iam_role_admin.name
}

resource "aws_iam_user" "iam_user_ci" {
  name = "${var.project}-ci"
}

resource "aws_iam_user_policy" "ci" {
  name = "ci"
  user = aws_iam_user.iam_user_ci.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }]
  })
}

# ---------------- exposición ----------------
resource "aws_lb" "alb_public" {
  name               = "${var.project}-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.sg_public.id]
  subnets            = [aws_subnet.subnet_pub.id, aws_subnet.subnet_priv.id]
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb_public.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
    }
  }
}

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
}

resource "aws_lambda_function" "lambda_api" {
  function_name    = "${var.project}-api"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
}

# ---------------- trazabilidad ----------------
# Anti-patrón: logging apagado
resource "aws_cloudtrail" "cloudtrail" {
  name           = "${var.project}-trail"
  s3_bucket_name = aws_s3_bucket.s3_logs.id
  enable_logging = false
}
