package aws.efs

default allow = false

# Allowable file system name prefixes
allowed_prefixes = {"dev-", "prod-"}

# Allow EFS file system creation if the name starts with an allowed prefix
allow {
    input.method == "efs:CreateFileSystem"
    some prefix
    startswith(input.file_system_name, prefix)
    allowed_prefixes[prefix]
}

deny_invalid_file_system_name {
    input.method == "efs:CreateFileSystem"
    not (some prefix; startswith(input.file_system_name, prefix); allowed_prefixes[prefix])
}
