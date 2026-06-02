terraform {
  backend "s3" {
    bucket     = "inspectra-demo-state"
    key        = "demo/terraform.tfstate"
    region     = "us-east-1"
    access_key = "raw-api-key-123456"
    secret_key = "super-secret-password"
  }
}

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "super-secret-password"
}

module "demo" {
  source = "git::https://example.com/demo-module.git"
}

resource "aws_security_group" "demo" {
  name = "demo-open-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public_demo" {
  bucket = "inspectra-demo-public"
  acl    = "public-read"
}
