import { ActiveDryRunJobReport } from "./ActiveDryRunJobReport";
import { ActiveDnsInventoryJobReport } from "./ActiveDnsInventoryJobReport";
import { ActiveDnsOsintJobReport } from "./ActiveDnsOsintJobReport";
import { ActiveHttpBasicHeaderReviewJobReport } from "./ActiveHttpBasicHeaderReviewJobReport";
import { ActiveHttpHeaderProbeJobReport } from "./ActiveHttpHeaderProbeJobReport";
import { ActiveNmapBasicJobReport } from "./ActiveNmapBasicJobReport";
import { ActiveTlsBasicJobReport } from "./ActiveTlsBasicJobReport";
import { ArchiveJobReport } from "./ArchiveJobReport";
import { CiCdConfigJobReport } from "./CiCdConfigJobReport";
import { ComposeConfigJobReport } from "./ComposeConfigJobReport";
import { DatabaseConfigJobReport } from "./DatabaseConfigJobReport";
import { DjangoConfigJobReport } from "./DjangoConfigJobReport";
import { DomainJobReport } from "./DomainJobReport";
import { DockerConfigJobReport } from "./DockerConfigJobReport";
import { ImageJobReport } from "./ImageJobReport";
import { K8sConfigJobReport } from "./K8sConfigJobReport";
import { ManifestJobReport } from "./ManifestJobReport";
import { NginxConfigJobReport } from "./NginxConfigJobReport";
import { NodePackageConfigJobReport } from "./NodePackageConfigJobReport";
import { PdfJobReport } from "./PdfJobReport";
import { ProjectArchiveJobReport } from "./ProjectArchiveJobReport";
import { RedisConfigJobReport } from "./RedisConfigJobReport";
import { SecretsReviewJobReport } from "./SecretsReviewJobReport";
import { SqlDatabaseConfigJobReport } from "./SqlDatabaseConfigJobReport";
import { SubdomainJobReport } from "./SubdomainJobReport";
import { TerraformConfigJobReport } from "./TerraformConfigJobReport";
import type { FileRecord, JobRecord } from "./types";
import { WebJobReport } from "./WebJobReport";

export default function JobResultReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  if (isActiveNmapBasicJob(job)) {
    return <ActiveNmapBasicJobReport job={job} />;
  }
  if (isActiveTlsBasicJob(job)) {
    return <ActiveTlsBasicJobReport job={job} />;
  }
  if (isActiveDnsInventoryJob(job)) {
    return <ActiveDnsInventoryJobReport job={job} />;
  }
  if (isActiveDnsOsintJob(job)) {
    return <ActiveDnsOsintJobReport job={job} />;
  }
  if (isActiveHttpBasicHeaderReviewJob(job)) {
    return <ActiveHttpBasicHeaderReviewJobReport job={job} />;
  }
  if (job.audit_type === "pdf_basic") {
    return <PdfJobReport job={job} file={file} />;
  }
  if (job.audit_type === "image_basic") {
    return <ImageJobReport job={job} file={file} />;
  }
  if (job.audit_type === "manifest_basic") {
    return <ManifestJobReport job={job} file={file} />;
  }
  if (job.audit_type === "archive_basic") {
    return <ArchiveJobReport job={job} file={file} />;
  }
  if (job.audit_type === "project_archive_basic") {
    return <ProjectArchiveJobReport job={job} file={file} />;
  }
  if (job.audit_type === "domain_basic") {
    return <DomainJobReport job={job} />;
  }
  if (job.audit_type === "subdomain_inventory_basic") {
    return <SubdomainJobReport job={job} />;
  }
  if (job.audit_type === "active_network_dry_run") {
    return <ActiveDryRunJobReport job={job} />;
  }
  if (job.audit_type === "active_http_header_probe") {
    return <ActiveHttpHeaderProbeJobReport job={job} />;
  }
  if (job.audit_type === "django_config_basic") {
    return <DjangoConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "docker_config_basic") {
    return <DockerConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "secrets_review_basic") {
    return <SecretsReviewJobReport job={job} file={file} />;
  }
  if (job.audit_type === "node_package_config_basic") {
    return <NodePackageConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "ci_cd_config_basic") {
    return <CiCdConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "k8s_config_basic") {
    return <K8sConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "terraform_config_basic") {
    return <TerraformConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "nginx_config_basic") {
    return <NginxConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "compose_config_basic") {
    return <ComposeConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "database_config_basic") {
    return <DatabaseConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "redis_config_basic") {
    return <RedisConfigJobReport job={job} file={file} />;
  }
  if (job.audit_type === "sql_database_config_basic") {
    return <SqlDatabaseConfigJobReport job={job} file={file} />;
  }
  return <WebJobReport job={job} />;
}

function isActiveNmapBasicJob(job: JobRecord): boolean {
  return job.audit_type === "active_nmap_basic" || job.result?.capability === "active_nmap_basic";
}

function isActiveTlsBasicJob(job: JobRecord): boolean {
  return job.audit_type === "active_tls_basic" || job.result?.capability === "active_tls_basic";
}

function isActiveDnsInventoryJob(job: JobRecord): boolean {
  return job.audit_type === "active_dns_inventory" || job.result?.capability === "active_dns_inventory";
}

function isActiveDnsOsintJob(job: JobRecord): boolean {
  return job.audit_type === "active_dns_osint" || job.result?.capability === "active_dns_osint";
}

function isActiveHttpBasicHeaderReviewJob(job: JobRecord): boolean {
  return job.audit_type === "active_http_basic_header_review" || job.result?.capability === "active_http_basic_header_review";
}
