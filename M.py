import yaml
from deepdiff import DeepDiff

# Function to load YAML file
def load_yaml(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f) or {}

# Paths to YAML files
file1 = "version-11.11.yaml"
file2 = "version-11.11.1.yaml"

# Load files
yaml1 = load_yaml(file1)
yaml2 = load_yaml(file2)

# Compute differences
diff = DeepDiff(yaml1, yaml2, ignore_order=True)

# Extract relevant changes
version_changes = diff.get("values_changed", {})
added_names = diff.get("dictionary_item_added", {})
removed_names = diff.get("dictionary_item_removed", {})

# Display results
print("===== Version Changes =====")
for key, value in version_changes.items():
    print(f"{key}: {value['old_value']} -> {value['new_value']}")

print("\n===== Newly Added Names =====")
for name in added_names:
    print(name)

print("\n===== Removed Names =====")
for name in removed_names:
    print(name)
