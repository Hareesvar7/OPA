package aws.s3

# Rule 1: S3-access-point-only-in-vpc
deny[{"bucket": bucket.name, "rule": "S3-access-point-only-in-vpc", "message": "Access point is not restricted to VPC"}] {
  bucket := input.buckets[_]
  bucket.access_point.vpc == false
}

# Rule 2: S3-bucket-default-lock-enabled
deny[{"bucket": bucket.name, "rule": "S3-bucket-default-lock-enabled", "message": "Object Lock is not enabled"}] {
  bucket := input.buckets[_]
  not bucket.lock.enabled
}

# Rule 3: S3-bucket-logging-enabled
deny[{"bucket": bucket.name, "rule": "S3-bucket-logging-enabled", "message": "Logging is not enabled"}] {
  bucket := input.buckets[_]
  bucket.logging.enabled == false
}

# Rule 4: S3-bucket-public-read-prohibited
deny[{"bucket": bucket.name, "rule": "S3-bucket-public-read-prohibited", "message": "Public read access is enabled"}] {
  bucket := input.buckets[_]
  bucket.acls.read == "public"
}

# Rule 5: S3-bucket-public-write-prohibited
deny[{"bucket": bucket.name, "rule": "S3-bucket-public-write-prohibited", "message": "Public write access is enabled"}] {
  bucket := input.buckets[_]
  bucket.acls.write == "public"
}

# Rule 6: S3-bucket-server-side-encryption-enabled
deny[{"bucket": bucket.name, "rule": "S3-bucket-server-side-encryption-enabled", "message": "Server-side encryption is not enabled"}] {
  bucket := input.buckets[_]
  bucket.encryption.sse_algorithm == ""
}

# Rule 7: S3-version-lifecycle-policy-check
deny[{"bucket": bucket.name, "rule": "S3-version-lifecycle-policy-check", "message": "Versioning is not enabled"}] {
  bucket := input.buckets[_]
  bucket.versioning.enabled == false
}

deny[{"bucket": bucket.name, "rule": "S3-version-lifecycle-policy-check", "message": "No lifecycle policy is configured for versioned bucket"}] {
  bucket := input.buckets[_]
  bucket.versioning.enabled == true
  count(bucket.lifecycle_rules) == 0
}
