package aws.ec2

default allow = false

# Define allowed security group inbound rule
allow {
  input.method == "ec2:AuthorizeSecurityGroupIngress"
  not input.ip_range == "0.0.0.0/0"
}

deny_unrestricted_ingress {
  input.method == "ec2:AuthorizeSecurityGroupIngress"
  input.ip_range == "0.0.0.0/0"
}
