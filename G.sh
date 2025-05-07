#!/bin/bash

# Set Azure subscription
az account set --subscription "${SUBSCRIPTION_ID}"
az account show

# Set Logic App path (adjust this to your actual path)
logicappPath="${LOGIC_APP_WORKFLOW_PATH:-$(pwd)/LogicApps}"
echo "Logic App workflows path: $logicappPath"

# Debug: List all files and directories
echo "Listing all files and directories under $logicappPath:"
find "$logicappPath" -type f

# Iterate over each folder containing workflow.json
echo "Searching for workflow.json files..."
find "$logicappPath" -type f -name "workflow.json" | while read workflowJsonPath; do
    workflowFolder=$(dirname "$workflowJsonPath")
    workflowName=$(basename "$workflowFolder")

    echo "Found workflow.json in folder: $workflowFolder"
    echo "Detected workflowName: $workflowName"

    # Simulate setting variables (used in pipelines)
    export mvso__task_setvariable_variable_WorkflowName__value="$workflowName"
    export mvso__task_setvariable_variable_WorkflowJsonPath__value="$workflowJsonPath"

    echo "Workflow Name: $mvso__task_setvariable_variable_WorkflowName__value"
    echo "Workflow JSON Path: $mvso__task_setvariable_variable_WorkflowJsonPath__value"
done
