package aws.ec2

default allow = false

# Approved instance types
allowed_instance_types = {"t2.micro", "t3.micro"}

# Allow only approved instance types to be launched
allow {
  input.method == "ec2:RunInstances"
  allowed_instance_types[input.instance_type]
}

deny_unapproved_instance_type {
  input.method == "ec2:RunInstances"
  not allowed_instance_types[input.instance_type]
}
