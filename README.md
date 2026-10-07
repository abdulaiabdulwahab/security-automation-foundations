# security-automation-foundations

Security Automation Foundations — Microsoft Sentinel + Logic Apps
Project Overview
This project demonstrates the foundations of Security Automation in Azure using:
- Microsoft Sentinel
- Azure Logic Apps
- Log Analytics
- Azure Activity Logs
- Sentinel Analytics Rules
- Sentinel Automation Rules
- Managed Identity
- Azure RBAC
The goal is to automatically detect an Azure administrative event, create a Sentinel incident, and trigger a Logic App playbook that adds investigation context to the incident.
Architecture
Azure Resource Activity
        ↓
Azure Activity Log
        ↓
Diagnostic Setting
        ↓
Log Analytics
        ↓
Microsoft Sentinel
        ↓
Scheduled Analytics Rule
        ↓
Security Alert
        ↓
Sentinel Incident
        ↓
Automation Rule
        ↓
Logic App Playbook
        ↓
Incident Comment + Investigation Task

Project Objectives
This project demonstrates how to:
- Create a Log Analytics workspace
- Enable Microsoft Sentinel
- Forward Azure Activity Logs to Log Analytics
- Query security data with KQL
- Create a Sentinel scheduled analytics rule
- Generate Sentinel incidents
- Create a Logic Apps security playbook
- Use managed identity for authentication
- Configure Sentinel RBAC permissions
- Automatically add comments and investigation tasks to incidents
- Troubleshoot Sentinel and Logic Apps integrations
Azure Resources
The project uses a dedicated resource group:
rg-security-automation-foundations

Example Log Analytics workspace:
law-secauto-foundations-7931

Example playbook:
pb-secauto-foundations-triage

Test resources use names similar to:
rg-secauto-trigger-12345

1. Configure Variables
LOCATION="canadacentral"

RG="rg-security-automation-foundations"

LAW="law-secauto-foundations-$RANDOM"

DIAG="log-sentinel"

TRIGGER_RG="rg-secauto-trigger-$RANDOM"

SUB_ID=$(az account show \
  --query id \
  --output tsv)

Verify:
echo "$RG"
echo "$LAW"
echo "$SUB_ID"

2. Create the Resource Group
az group create \
  --name "$RG" \
  --location "$LOCATION"

3. Create Log Analytics Workspace
az monitor log-analytics workspace create \
  --resource-group "$RG" \
  --workspace-name "$LAW" \
  --location "$LOCATION" \
  --sku PerGB2018 \
  --retention-time 30

Get the workspace resource ID:
LAW_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RG" \
  --workspace-name "$LAW" \
  --query id \
  --output tsv)

Get the workspace customer ID:
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RG" \
  --workspace-name "$LAW" \
  --query customerId \
  --output tsv)

4. Enable Microsoft Sentinel
az extension add \
  --name log-analytics-solution \
  --upgrade

Then:
az monitor log-analytics solution create \
  --resource-group "$RG" \
  --solution-type SecurityInsights \
  --workspace "$LAW"

Using the workspace name avoids Git Bash converting Azure resource IDs into Windows paths.
5. Send Azure Activity Logs to Log Analytics
Create a subscription diagnostic setting:
MSYS_NO_PATHCONV=1 az monitor diagnostic-settings subscription create \
  --name "$DIAG" \
  --workspace "$LAW_ID" \
  --location "$LOCATION" \
  --logs '[{"category":"Administrative","enabled":true}]'

Verify:
az monitor diagnostic-settings subscription show \
  --name "$DIAG" \
  --output jsonc

The workspace ID should point to the project Log Analytics workspace.
6. Generate Test Activity
Create a temporary resource group:
TRIGGER_RG="rg-secauto-trigger-$RANDOM"

az group create \
  --name "$TRIGGER_RG" \
  --location "$LOCATION"

This generates an Azure Activity Log event such as:
Microsoft.Resources/subscriptions/resourcegroups/write

Verify the source Activity Log:
az monitor activity-log list \
  --offset 1h \
  --query "[?contains(resourceId, '$TRIGGER_RG')].{Time:eventTimestamp,Operation:operationName.value,Status:status.value}" \
  --output table

7. Verify Log Analytics Ingestion
Check whether Azure Activity events are reaching the workspace:
az monitor log-analytics query \
  --workspace "$WORKSPACE_ID" \
  --analytics-query "
AzureActivity
| where TimeGenerated > ago(4h)
| order by TimeGenerated desc
| take 50
" \
  --output table

A more specific query:
az monitor log-analytics query \
  --workspace "$WORKSPACE_ID" \
  --analytics-query "
AzureActivity
| where TimeGenerated > ago(4h)
| where OperationNameValue =~ 'Microsoft.Resources/subscriptions/resourceGroups/write'
| project
    TimeGenerated,
    OperationNameValue,
    ActivityStatusValue,
    ResourceGroup,
    ResourceId,
    Caller,
    CorrelationId
| order by TimeGenerated desc
" \
  --output table

8. Create a Sentinel Analytics Rule
In Microsoft Defender:
Microsoft Sentinel
→ Configuration
→ Analytics
→ Create
→ Scheduled query rule

Name:
Security Automation Foundations - Resource Group Created

Severity:
Medium

Example KQL:
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue =~ "Microsoft.Resources/subscriptions/resourceGroups/write"
| project
    TimeGenerated,
    Caller,
    ResourceGroup,
    ResourceId,
    OperationNameValue,
    ActivityStatusValue,
    CorrelationId

Recommended schedule:
Run every: 5 minutes
Lookup period: 1 hour
Threshold: Greater than 0

Enable:
Create incidents from alerts triggered by this analytics rule

9. Create the Logic App Playbook
Create:
pb-secauto-foundations-triage

Use:
Microsoft Sentinel incident

as the trigger.
The intended workflow is:
Microsoft Sentinel incident
        ↓
Add comment to incident (V3)
        ↓
Add task to incident

The incident ARM ID should come from the Sentinel incident trigger.
Example expression:
triggerBody()?['object']?['id']

Do not manually type:
Incident ARM ID

as plain text.
10. Configure Managed Identity
Enable:
System-assigned managed identity

for the Logic App.
Get the identity:
PLAYBOOK="pb-secauto-foundations-triage"

PB_PRINCIPAL_ID=$(az resource show \
  --resource-group "$RG" \
  --name "$PLAYBOOK" \
  --resource-type "Microsoft.Logic/workflows" \
  --query identity.principalId \
  --output tsv)

11. Give the Playbook Sentinel Permissions
Get the resource group ID:
RG_ID=$(az group show \
  --name "$RG" \
  --query id \
  --output tsv)

Assign:
MSYS_NO_PATHCONV=1 az role assignment create \
  --assignee-object-id "$PB_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" \
  --scope "$RG_ID"

This allows the Logic App to modify Sentinel incidents.
12. Give Sentinel Permission to Run the Playbook
The Sentinel service principal also requires permission to execute the Logic App.
Find it:
SENTINEL_SP_ID=$(az ad sp list \
  --display-name "Azure Security Insights" \
  --query "[0].id" \
  --output tsv)

Assign:
MSYS_NO_PATHCONV=1 az role assignment create \
  --assignee-object-id "$SENTINEL_SP_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Automation Contributor" \
  --scope "$RG_ID"

13. Create a Sentinel Automation Rule
Navigate to:
Microsoft Sentinel
→ Configuration
→ Automation
→ Automation rules
→ Create

Configure:
Name:
Auto-triage foundations incidents

Trigger:
When incident is created

Condition:
Analytics rule name
contains
Security Automation Foundations - Resource Group Created

Action:
Run playbook

Select:
pb-secauto-foundations-triage

14. Test the Complete Workflow
Generate a new Azure event:
TRIGGER_RG="rg-secauto-trigger-$RANDOM"

az group create \
  --name "$TRIGGER_RG" \
  --location "$LOCATION"

The expected flow is:
Resource group created
        ↓
Azure Activity Log
        ↓
AzureActivity table
        ↓
Sentinel Analytics Rule
        ↓
Security Alert
        ↓
Incident
        ↓
Automation Rule
        ↓
Logic App
        ↓
Comment + Task

Troubleshooting
Git Bash converts Azure resource IDs
Problem:
C:/Program Files/Git/subscriptions/...

instead of:
/subscriptions/...

Use:
MSYS_NO_PATHCONV=1 az ...

when passing Azure resource IDs.
AzureActivity is empty
First verify that Azure recorded the event:
az monitor activity-log list \
  --offset 1h \
  --output table

Then verify the diagnostic setting:
az monitor diagnostic-settings subscription show \
  --name "$DIAG" \
  --output jsonc

Then query broadly:
AzureActivity
| where TimeGenerated > ago(24h)
| order by TimeGenerated desc

Analytics rule creates no incident
Verify:
Analytics Rule = Enabled

and:
Create incidents from alerts = Enabled

Also test the rule's KQL manually.
Logic App reports Incident Arm id missing
Do not manually run the Sentinel incident trigger from Logic Apps.
The playbook must receive a real Sentinel incident payload.
The incident ARM ID should come from:
Microsoft Sentinel incident
→ Incident ARM ID

or:
triggerBody()?['object']?['id']

For each fails with alerts = null
A simple incident comment/task workflow does not require a For each.
Use:
Microsoft Sentinel incident
        ↓
Add comment
        ↓
Add task

instead.
Cleanup
Remove the subscription diagnostic setting:
az monitor diagnostic-settings subscription delete \
  --name "$DIAG"

Delete the temporary trigger resource group:
az group delete \
  --name "$TRIGGER_RG" \
  --yes \
  --no-wait

Delete the main project:
az group delete \
  --name "$RG" \
  --yes \
  --no-wait

Skills Demonstrated
This project demonstrates practical experience with:
Microsoft Sentinel
Azure Logic Apps
Azure Monitor
Log Analytics
KQL
Security Analytics Rules
Security Automation Rules
SOAR
Managed Identities
Azure RBAC
Incident Response Automation
Azure CLI
Security Monitoring

Project Summary
The project builds a simple Azure-native security automation pipeline in which administrative activity is collected through Azure Monitor, analyzed by Microsoft Sentinel, converted into security incidents, and automatically processed by a Logic Apps playbook.
It demonstrates the core SOAR workflow:
Detect
→ Alert
→ Incident
→ Automate
→ Investigate

This provides a foundation for more advanced security automation workflows such as automated containment, account disabling, NSG remediation, ticket creation, Teams notifications, threat-intelligence enrichment, and automated DevSecOps response.