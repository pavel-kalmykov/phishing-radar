output "bq_dataset" {
  value = google_bigquery_dataset.phishing_radar.dataset_id
}

output "gcs_bucket" {
  value = google_storage_bucket.raw.name
}

output "dashboard_service_account" {
  value = google_service_account.dashboard.email
}

output "pipeline_service_account" {
  value = google_service_account.pipeline.email
}
