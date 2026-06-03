import type { AuditType } from "./types";

export type AuditCategoryId =
  | "file_basics"
  | "archive_structure"
  | "authorized_web_domain"
  | "active_network"
  | "app_config"
  | "containers_wiring"
  | "infra_deployment"
  | "web_edge"
  | "data_layer"
  | "secrets"
  | "unknown";

export type AuditSourceFamily = "file" | "archive" | "authorized_target" | "target" | "unknown";

export type AuditTypeMetadata = {
  auditType: string;
  label: string;
  categoryId: AuditCategoryId;
  categoryLabel: string;
  sourceFamily: AuditSourceFamily;
  shortDescription: string;
};

export const AUDIT_TYPE_ORDER: AuditType[] = [
  "pdf_basic",
  "image_basic",
  "manifest_basic",
  "archive_basic",
  "project_archive_basic",
  "web_basic",
  "domain_basic",
  "subdomain_inventory_basic",
  "active_network_dry_run",
  "active_http_header_probe",
  "django_config_basic",
  "docker_config_basic",
  "secrets_review_basic",
  "node_package_config_basic",
  "ci_cd_config_basic",
  "k8s_config_basic",
  "terraform_config_basic",
  "nginx_config_basic",
  "compose_config_basic",
  "database_config_basic",
  "redis_config_basic",
  "sql_database_config_basic"
];

const CATEGORY_LABELS: Record<AuditCategoryId, string> = {
  file_basics: "File basics",
  archive_structure: "Archive structure",
  authorized_web_domain: "Authorized web/domain",
  active_network: "Active / Network",
  app_config: "App config",
  containers_wiring: "Containers & wiring",
  infra_deployment: "Infrastructure & deployment",
  web_edge: "Web edge",
  data_layer: "Data layer",
  secrets: "Secrets",
  unknown: "Unknown"
};

function metadata(
  auditType: AuditType,
  label: string,
  categoryId: AuditCategoryId,
  sourceFamily: AuditSourceFamily,
  shortDescription: string
): AuditTypeMetadata {
  return {
    auditType,
    label,
    categoryId,
    categoryLabel: CATEGORY_LABELS[categoryId],
    sourceFamily,
    shortDescription
  };
}

export const AUDIT_TYPE_CATALOG: Record<AuditType, AuditTypeMetadata> = {
  pdf_basic: metadata("pdf_basic", "PDF basic", "file_basics", "file", "Passive PDF metadata and validation review."),
  image_basic: metadata("image_basic", "Image basic", "file_basics", "file", "Passive image metadata and privacy-signal review."),
  manifest_basic: metadata("manifest_basic", "Manifest basic", "file_basics", "file", "Passive package manifest review."),
  archive_basic: metadata("archive_basic", "Archive basic", "archive_structure", "archive", "Passive archive structure review."),
  project_archive_basic: metadata(
    "project_archive_basic",
    "Project manifests",
    "archive_structure",
    "archive",
    "Passive project manifest review inside archives."
  ),
  web_basic: metadata("web_basic", "Web basic", "authorized_web_domain", "authorized_target", "Authorized basic web review."),
  domain_basic: metadata("domain_basic", "Domain baseline", "authorized_web_domain", "authorized_target", "Authorized domain baseline review."),
  subdomain_inventory_basic: metadata(
    "subdomain_inventory_basic",
    "Subdomain inventory",
    "authorized_web_domain",
    "authorized_target",
    "Authorized subdomain inventory review."
  ),
  active_network_dry_run: metadata(
    "active_network_dry_run",
    "Active network dry-run",
    "active_network",
    "target",
    "Dry-run planning for explicitly authorized targets; no network traffic."
  ),
  active_http_header_probe: metadata(
    "active_http_header_probe",
    "Authorized HTTP header probe",
    "active_network",
    "target",
    "Sends one authorized HTTP HEAD request and records redacted headers; no redirects or body read."
  ),
  django_config_basic: metadata("django_config_basic", "Django config", "app_config", "archive", "Passive Django config review."),
  docker_config_basic: metadata("docker_config_basic", "Docker config", "containers_wiring", "archive", "Passive Docker config review."),
  secrets_review_basic: metadata("secrets_review_basic", "Secrets review", "secrets", "archive", "Passive secret-exposure indicator review."),
  node_package_config_basic: metadata(
    "node_package_config_basic",
    "Node package config",
    "app_config",
    "archive",
    "Passive Node package/config review."
  ),
  ci_cd_config_basic: metadata("ci_cd_config_basic", "CI/CD config", "infra_deployment", "archive", "Passive CI/CD workflow config review."),
  k8s_config_basic: metadata("k8s_config_basic", "Kubernetes config", "infra_deployment", "archive", "Passive Kubernetes manifest review."),
  terraform_config_basic: metadata(
    "terraform_config_basic",
    "Terraform config",
    "infra_deployment",
    "archive",
    "Passive Terraform/IaC config review."
  ),
  nginx_config_basic: metadata("nginx_config_basic", "Nginx config", "web_edge", "archive", "Passive Nginx/web-edge config review."),
  compose_config_basic: metadata(
    "compose_config_basic",
    "Compose config",
    "containers_wiring",
    "archive",
    "Passive Docker Compose service-wiring review."
  ),
  database_config_basic: metadata("database_config_basic", "Database config", "data_layer", "archive", "Passive database config review."),
  redis_config_basic: metadata("redis_config_basic", "Redis config", "data_layer", "archive", "Passive Redis/Sentinel config review."),
  sql_database_config_basic: metadata(
    "sql_database_config_basic",
    "SQL DB config",
    "data_layer",
    "archive",
    "Passive SQL database config review."
  )
};

export function getAuditTypeMetadata(auditType: AuditType | string): AuditTypeMetadata {
  return (
    AUDIT_TYPE_CATALOG[auditType as AuditType] ?? {
      auditType,
      label: auditType,
      categoryId: "unknown",
      categoryLabel: CATEGORY_LABELS.unknown,
      sourceFamily: "unknown",
      shortDescription: "Unregistered audit type."
    }
  );
}
