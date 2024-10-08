package aws.efs

default allow = false

# Allow EFS file system creation with specific throughput modes
allow {
    input.method == "efs:CreateFileSystem"
    input.throughput_mode == "bursting"
} 

allow {
    input.method == "efs:CreateFileSystem"
    input.throughput_mode == "provisioned"
}

deny_invalid_throughput_mode {
    input.method == "efs:CreateFileSystem"
    input.throughput_mode != "bursting"
    input.throughput_mode != "provisioned"
}
