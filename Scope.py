import os
import requests

# environment secrets
jira_username = os.environ['JIRA_USER']
jira_token = os.environ['JIRA_TOKEN']
github_token = os.environ['MANIFEST_GITHUB_TOKEN']

# FIXED VERSION from environment variable (set by workflow_dispatch input)
FIXED_VERSION = os.environ.get('FIXED_VERSION', 'SFP.R.13.3')

# JQL Query to get closed Jira tickets for given FIXED_VERSION
jql = f'project = SMAR AND fixVersion = "{FIXED_VERSION}" and status = Closed'

# Make API call to Jira
response = requests.get(
    "https://jira.tools.deloitteinnovation.us/rest/api/2/search",
    params={'jql': jql},
    auth=(jira_username, jira_token),
    headers={"Content-Type": "application/json"},
    timeout=10
)

if response.status_code != 200:
    print(f"Error fetching tickets: {response.status_code} {response.text}")
    data = {"issues": []}
else:
    data = response.json()

# GitHub org info
github_org = "Deloitte-US-Innovation-Technology"
gh_headers = {
    "Authorization": f"token {github_token}",
    "Accept": "application/vnd.github.v3+json"
}

output_lines = []
output_lines.append(f"Scope for FIXED_VERSION: {FIXED_VERSION}")
output_lines.append("\n----- Jira to GitHub Release PRs & Creators -----")

# Loop through Jira issues
for issue in data.get('issues', []):
    key = issue['key']

    search_url = "https://api.github.com/search/issues"
    # Only search for merged PRs with the Jira key
    q = f'is:pr is:merged {key} org:{github_org}'
    gh_response = requests.get(search_url, params={'q': q}, headers=gh_headers, timeout=10)

    if gh_response.status_code != 200:
        output_lines.append(f"\nJira Issue: {key}")
        output_lines.append("  Error fetching PRs from GitHub")
        continue

    prs = gh_response.json().get('items', [])
    filtered_prs = []

    for pr in prs:
        pr_html_url = pr['html_url']
        pr_title = pr['title']
        pr_number = int(pr_html_url.split('/')[-1])

        # 🔹 Filter only PRs with title "chore: release main"
        if pr_title.strip().lower() == "chore: release main":
            # Get PR details to fetch creator info
            repo_url = pr['repository_url']
            repo_name = repo_url.split('/')[-1]
            pr_details_url = f"https://api.github.com/repos/{github_org}/{repo_name}/pulls/{pr_number}"
            pr_details_resp = requests.get(pr_details_url, headers=gh_headers, timeout=10)
            if pr_details_resp.status_code == 200:
                pr_details = pr_details_resp.json()
                creator = pr_details['user']['login']
                filtered_prs.append({
                    "title": pr_title,
                    "url": pr_html_url,
                    "creator": creator
                })

    # Append results to output
    output_lines.append(f"\nJira Issue: {key}")
    if filtered_prs:
        output_lines.append("  Matched Release PRs:")
        for pr in filtered_prs:
            output_lines.append(f"    - {pr['title']} ({pr['url']}) by {pr['creator']}")
    else:
        output_lines.append("  No matching release PRs found.")

# Save to file
output_filename = "scope_output.txt"
with open(output_filename, "w", encoding="utf-8") as f:
    f.write("\n".join(output_lines))

# Print results
for line in output_lines:
    print(line)
