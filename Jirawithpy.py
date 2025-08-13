name: Jira Ticket Extractor

on:
  workflow_dispatch:

jobs:
  extract_tickets:
    runs-on: ubuntu-latest
    env:
      JIRA_USER: ${{ secrets.JIRA_USER }}
      JIRA_TOKEN: ${{ secrets.JIRA_TOKEN }}
      JIRA_URL: ${{ secrets.JIRA_URL }}
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.x'

      - name: Run Python script
        run: |
          python jira_fetch.py
