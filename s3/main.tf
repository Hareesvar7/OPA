# main.tf

provider "aws" {
  region = "us-east-1"
}

# Create an S3 bucket
resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
  
  # Block public access by default
  acl    = "private"

  # Server-side encryption enabled for all objects in the bucket
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  # Add tags for cost allocation (as required by the industrial policy)
  tags = {
    "cost-center" = "finance"
    "project-id"  = "12345"
  }
}

# Example S3 object
resource "aws_s3_bucket_object" "example_object" {
  bucket = aws_s3_bucket.example.bucket
  key    = "example_object"
  source = "example_file.txt"
  
  # Enable server-side encryption for the object
  server_side_encryption = "AES256"

  # Tags for the object
  tags = {
    "cost-center" = "finance"
    "project-id"  = "12345"
  }
}

# Enforce retention policies for bucket objects
resource "aws_s3_bucket_lifecycle_configuration" "example_lifecycle" {
  bucket = aws_s3_bucket.example.id

  rule {
    id     = "Enforce retention"
    status = "Enabled"

    expiration {
      days = 30  # Minimum retention period as per the OPA policy
    }
  }
}
