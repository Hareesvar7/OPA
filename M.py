import yaml
import json
from deepdiff import DeepDiff

try:
    with open("version-11.11.yaml", "r") as f1, open("version-11.11.1.yaml", "r") as f2:
        yaml1 = yaml.safe_load(f1) or {}  # Handle empty files
        yaml2 = yaml.safe_load(f2) or {}

    diff = DeepDiff(yaml1, yaml2, ignore_order=True)

    if diff:
        print(json.dumps(diff, indent=2))
    else:
        print("No differences found between the two YAML files.")

except FileNotFoundError as e:
    print(f"Error: {e}")
except yaml.YAMLError as e:
    print(f"Error parsing YAML: {e}")
