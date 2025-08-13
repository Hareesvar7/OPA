import os
import requests

# Read secrets from environment variables
username = os.environ['JIRA_USER']
token = os.environ['JIRA_TOKEN']
jira_url = os.environ['JIRA_URL']

# Fixed version to filter
FIXED_VERSION = "1.2.3"

# JQL Query
jql = f'project=SMAR AND status=Closed AND fixVersion="{FIXED_VERSION}"'

# Make API call
response = requests.get(
    f"{jira_url}/rest/api/2/search",
    params={'jql': jql},
    auth=(username, token),
    headers={"Content-Type": "application/json"}
)

if response.status_code != 200:
    print(f"Error fetching tickets: {response.status_code} {response.text}")
else:
    data = response.json()
    keys = [issue['key'] for issue in data.get('issues', [])]
    print("----- Ticket Numbers -----")
    for key in keys:
        print(key)
