terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "assets" {
  bucket = "bad-service-assets"
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  engine         = "postgres"
  instance_class = "db.t4g.micro"
}

resource "aws_iam_policy" "app" {
  name = "app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
