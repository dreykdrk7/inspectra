variable "password" {
  default = "super-secret-password"
}

output "api_key" {
  value     = "raw-api-key-123456"
  sensitive = false
}

provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "super-secret-password"
}
