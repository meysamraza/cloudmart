provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "cloudmart_bucket" {
  bucket = "cloudmart-training-bucket"
}

# VULN: public access block disabled — bucket can be made public
resource "aws_s3_bucket_public_access_block" "cloudmart_bucket_access" {
  bucket = aws_s3_bucket.cloudmart_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULN: security group open to the world on port 22
resource "aws_security_group" "cloudmart_sg" {
  name        = "cloudmart-sg"
  description = "Security group for CloudMart lab"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}