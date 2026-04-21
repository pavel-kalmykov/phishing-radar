terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required APIs (idempotent)
resource "google_project_service" "services" {
  for_each = toset([
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "iam.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# BigQuery dataset
resource "google_bigquery_dataset" "phishing_radar" {
  dataset_id    = var.bq_dataset_id
  location      = var.region
  description   = "Phishing Radar: CT logs streaming + threat intel batch correlation"
  friendly_name = "Phishing Radar"

  labels = {
    project = "phishing-radar"
    course  = "de-zoomcamp-2026"
  }

  depends_on = [google_project_service.services]
}

# GCS bucket for raw lake + Flink checkpoints + dlt staging
resource "google_storage_bucket" "raw" {
  name          = var.gcs_bucket_name
  location      = var.region
  force_destroy = true
  storage_class = "STANDARD"

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    project = "phishing-radar"
  }

  depends_on = [google_project_service.services]
}

# Service account for the Streamlit dashboard (read-only on BQ)
resource "google_service_account" "dashboard" {
  account_id   = "phishing-radar-dashboard"
  display_name = "Phishing Radar Streamlit dashboard"
  description  = "Read-only access to phishing_radar dataset"
}

resource "google_project_iam_member" "dashboard_bq_viewer" {
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = "serviceAccount:${google_service_account.dashboard.email}"

  condition {
    title       = "only_phishing_radar_dataset"
    description = "Scoped to the phishing_radar dataset"
    expression  = "resource.name.startsWith(\"projects/${var.project_id}/datasets/${var.bq_dataset_id}\")"
  }
}

resource "google_project_iam_member" "dashboard_bq_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.dashboard.email}"
}

# Service account for the batch pipeline (write BQ + GCS)
resource "google_service_account" "pipeline" {
  account_id   = "phishing-radar-pipeline"
  display_name = "Phishing Radar batch pipeline"
  description  = "Writes to phishing_radar dataset and raw bucket"
}

resource "google_bigquery_dataset_iam_member" "pipeline_editor" {
  dataset_id = google_bigquery_dataset.phishing_radar.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.pipeline.email}"
}

resource "google_project_iam_member" "pipeline_bq_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.pipeline.email}"
}

resource "google_storage_bucket_iam_member" "pipeline_gcs_admin" {
  bucket = google_storage_bucket.raw.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.pipeline.email}"
}
