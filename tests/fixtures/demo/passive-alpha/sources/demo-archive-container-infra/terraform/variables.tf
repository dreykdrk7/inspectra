variable "db_password" {
  type    = string
  default = "super-secret-password"
}

output "api_key" {
  value     = "raw-api-key-123456"
  sensitive = false
}
