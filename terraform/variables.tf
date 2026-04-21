variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "phishing-radar-putopavel"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "europe-southwest1"
}

variable "bq_dataset_id" {
  description = "BigQuery dataset ID"
  type        = string
  default     = "phishing_radar"
}

variable "gcs_bucket_name" {
  description = "GCS bucket for raw data lake"
  type        = string
  default     = "phishing-radar-putopavel-raw"
}
