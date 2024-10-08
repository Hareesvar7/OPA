package aws.ec2

default allow = false

# List of approved AMIs (example AMI IDs)
approved_amis = {"ami-0123456789abcdef0", "ami-0987654321abcdef0"}

# Allow only approved AMIs for instance creation
allow {
  input.method == "ec2:RunInstances"
  approved_amis[input.ami_id]
}

deny_unapproved_ami {
  input.method == "ec2:RunInstances"
  not approved_amis[input.ami_id]
}
