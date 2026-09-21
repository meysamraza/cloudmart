provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "cloudmart_bucket" {
  bucket = "cloudmart-training-bucket"
}

resource "aws_s3_bucket_public_access_block" "cloudmart_bucket_access" {
  bucket = aws_s3_bucket.cloudmart_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "cloudmart_sg" {
  name        = "cloudmart-sg"
  description = "Security group for CloudMart lab"

  ingress {
    description = "Allow SSH from trusted internal network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}