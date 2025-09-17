import os
import requests
import re
from bs4 import BeautifulSoup

# environment secrets
jira_username = os.environ['JIRA_USER']
jira_token = os.environ['JIRA_TOKEN']
github_token = os.environ['MANIFEST_GITHUB_TOKEN']

# FIXED VERSION from environment variable (set by workflow_dispatch input)
FIXED_VERSION = os.environ.get('FIXED_VERSION', 'SFP.R.13.3')

# JQL Query
jql = f'project = SMAR AND fixVersion = "{FIXED_VERSION}" and status = Closed'

# Make API call to Jira
response = requests.get(
    "https://jira.tools.deloitteinnovation.us/rest/api/2/search",
    params={'jql': jql},  # Request all fields
    auth=(jira_username, jira_token),
    headers={"Content-Type": "application/json"},
    timeout=10
)

if response.status_code != 200:
    print(f"Error fetching tickets: {response.status_code} {response.text}")
    keys = []
else:
    data = response.json()
    keys = [issue['key'] for issue in data.get('issues', [])]

# GitHub org info
github_org = "Deloitte-US-Innovation-Technology"
gh_headers = {
    "Authorization": f"token {github_token}",
    "Accept": "application/vnd.github.v3+json"
}

output_lines = []
output_lines.append(f"Scope for FIXED_VERSION: {FIXED_VERSION}")
output_lines.append("\n----- Jira to GitHub Release PR Mapping -----")
if response.status_code == 200:
    for issue in data.get('issues', []):
        key = issue['key']
        description = issue['fields'].get('description', '')
        found_prs = []
        seen_pr_ids = set()
        search_url = "https://api.github.com/search/issues"
        # Search for merged PRs with the Jira key in title/body across the org
        q = f'is:pr is:merged {key} org:{github_org}'
        gh_response = requests.get(search_url, params={'q': q}, headers=gh_headers, timeout=10)
        pr_data = gh_response.json()
        # Rate limit handling
        if pr_data.get('status') == 403 and 'rate limit' in pr_data.get('message', ''):
            output_lines.append("Rate limit hit, sleeping for 60 seconds...")
            import time
            time.sleep(60)
            continue
        prs = pr_data.get('items', [])
        for pr in prs:
            pr_id = pr['id']
            pr_title = pr['title']
            # Filter for PRs with "chore:" prefix only
            if re.match(r'^chore:\s*', pr_title, re.IGNORECASE):
                if pr_id not in seen_pr_ids:
                    # Get repo name and PR number
                    repo_url = pr['repository_url']
                    repo_name = repo_url.split('/')[-1]
                    pr_html_url = pr['html_url']
                    pr_number = int(pr_html_url.split('/')[-1])
                    # Get PR details for creator information
                    pr_details_url = f"https://api.github.com/repos/{github_org}/{repo_name}/pulls/{pr_number}"
                    pr_details_resp = requests.get(pr_details_url, headers=gh_headers, timeout=10)
                    pr_details = pr_details_resp.json()
                    
                    # Get creator info
                    creator = pr_details.get('user', {})
                    creator_login = creator.get('login', 'Unknown')
                    creator_id = creator.get('id', 'Unknown')
                    creator_name = creator.get('name', creator_login)
                    
                    # Check if PR is already approved
                    reviews_url = f"https://api.github.com/repos/{github_org}/{repo_name}/pulls/{pr_number}/reviews"
                    reviews_resp = requests.get(reviews_url, headers=gh_headers, timeout=10)
                    reviews = reviews_resp.json()
                    
                    already_approved = any(review.get('state') == 'APPROVED' for review in reviews)
                    
                    # Approve the PR if not already approved
                    if not already_approved:
                        approve_url = f"https://api.github.com/repos/{github_org}/{repo_name}/pulls/{pr_number}/reviews"
                        approve_data = {
                            "body": "Automatically approved via script - chore release PR",
                            "event": "APPROVE"
                        }
                        approve_resp = requests.post(approve_url, json=approve_data, headers=gh_headers, timeout=10)
                        
                        if approve_resp.status_code == 200:
                            approval_status = "APPROVED_SUCCESSFULLY"
                        else:
                            approval_status = f"APPROVAL_FAILED_STATUS_CODE_{approve_resp.status_code}"
                    else:
                        approval_status = "ALREADY_APPROVED"
                    
                    pr_info = f"{repo_name}: {pr_title} ({pr_html_url}) - Creator: {creator_name} (ID: {creator_id}, Login: {creator_login}) - Approval_Status: {approval_status}"
                    found_prs.append(pr_info)
                    seen_pr_ids.add(pr_id)
        output_lines.append(f"\nJira Issue: {key}")
        if found_prs:
            output_lines.append("  Associated chore PRs:")
            for pr_info in found_prs:
                output_lines.append(f"    - {pr_info}")
        else:
            output_lines.append("  No associated chore PRs found.")
        output_lines.append("")
else:
    output_lines.append("No issues found or error fetching issues.")

# Write to file FIRST
output_filename = "scope_output.txt"
with open(output_filename, "w", encoding="utf-8") as f:
    f.write("\n".join(output_lines))

# Then print to console ONCE
print("\n".join(output_lines))
