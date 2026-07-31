terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Variables
variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for deployment"
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Environment name"
}

variable "db_password" {
  type        = string
  sensitive   = true
  description = "Password for RDS PostgreSQL database"
}

# 1. ECR Repository
resource "aws_ecr_repository" "app" {
  name                 = "governed-audit-log"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# 2. VPC & Networking
resource "aws_default_vpc" "default" {}

resource "aws_default_subnet" "default_az1" {
  availability_zone = "${var.aws_region}a"
}

resource "aws_default_subnet" "default_az2" {
  availability_zone = "${var.aws_region}b"
}

# 3. Security Groups
resource "aws_security_group" "db" {
  name        = "governed-audit-db-sg"
  description = "Allow inbound postgres access"
  vpc_id      = aws_default_vpc.default.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Configured open for connection demo; restrict in production VPC
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 4. RDS PostgreSQL Database
resource "aws_db_instance" "postgres" {
  identifier             = "governed-audit-db"
  allocated_storage      = 20
  max_allocated_storage  = 100
  db_name                = "governed_audit_db"
  engine                 = "postgres"
  engine_version         = "15"
  instance_class         = "db.t4g.micro"
  username               = "audit_user"
  password               = var.db_password
  parameter_group_name   = "default.postgres15"
  skip_final_snapshot    = true
  publicly_accessible    = true
  vpc_security_group_ids = [aws_security_group.db.id]
}

# 5. IAM Roles for App Runner
resource "aws_iam_role" "apprunner_ecr_access" {
  name = "AppRunnerECRAccessRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "build.apprunner.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "apprunner_ecr_policy" {
  role       = aws_iam_role.apprunner_ecr_access.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess"
}

# 6. AWS App Runner Service
resource "aws_apprunner_service" "app" {
  service_name = "governed-audit-log-service"

  source_configuration {
    authentication_configuration {
      access_role_arn = aws_iam_role.apprunner_ecr_access.arn
    }

    image_repository {
      image_identifier      = "${aws_ecr_repository.app.repository_url}:latest"
      image_repository_type = "ECR"
      image_configuration {
        port = "8000"
        
        runtime_environment_variables = {
          DATABASE_URL        = "postgresql://audit_user:${var.db_password}@${aws_db_instance.postgres.endpoint}/governed_audit_db"
          PII_ENCRYPTION_KEY  = "gK4P1Xz8Z9R7W2Y6A3B5C8D1E4F7G0H3I6J9K2L5M8N="
          JWT_SECRET_KEY      = "governed-audit-log-jwt-secret-change-in-prod"
          ADMIN_API_KEY       = "admin-secret-key-123"
          AUDITOR_API_KEY     = "auditor-secret-key-456"
          SERVICE_API_KEY     = "service-secret-key-789"
          LLM_PROVIDER        = "mock"
        }
      }
    }
    auto_deployments_enabled = false
  }

  instance_configuration {
    cpu    = "1024" # 1 vCPU
    memory = "2048" # 2 GB Memory
  }

  tags = {
    Environment = var.environment
  }
}

# Outputs
output "ecr_repository_url" {
  value       = aws_ecr_repository.app.repository_url
  description = "Push ECR image here"
}

output "app_runner_url" {
  value       = aws_apprunner_service.app.service_url
  description = "Public URL of the deployed Governed Audit Log API"
}
