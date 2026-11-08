# Setup walkthrough (Phase 0-1)

Everything runs from Windows PowerShell on the laptop. Commands that need
**admin PowerShell** say so.

## 1. Deploy the AWS side

```powershell
cd $HOME\Documents\SOC-\terraform
copy terraform.tfvars.example terraform.tfvars   # then put your email in it
aws login
$env:AWS_PROFILE = "hlz"
terraform init
terraform plan
terraform apply
```

Confirm the **AWS Notification - Subscription Confirmation** email, or alarms
will fire without reaching you.

## 2. Create the shipper's access key (do this yourself)

In the AWS console: **IAM > Users > hsoc-laptop-shipper > Security credentials >
Create access key > "Application running outside AWS"**. Then:

```powershell
aws configure --profile hsoc-shipper
# paste the key ID and secret, region us-east-2, output json
```

Never paste the secret into chat, a file in this repo, or a screenshot.

## 3. Check the Security log records failed logons

```powershell
auditpol /get /subcategory:"Logon"
```
"Failure" must be listed. If not (admin PowerShell):
```powershell
auditpol /set /subcategory:"Logon" /failure:enable
```

## 4. Install Sysmon (admin PowerShell)

Download Sysmon from Microsoft Sysinternals
(https://learn.microsoft.com/sysinternals/downloads/sysmon), unzip it, then:

```powershell
.\Sysmon64.exe -accepteula -i $HOME\Documents\SOC-\sysmon\sysmon-homesoc.xml
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

## 5. Install and start the CloudWatch Agent (admin PowerShell)

Download and run the Windows MSI
(https://amazoncloudwatch-agent.s3.amazonaws.com/windows/amd64/latest/amazon-cloudwatch-agent.msi).
Version 1.300059.0 or later is required for the `event_ids` filter.

```powershell
copy $HOME\Documents\SOC-\agent\common-config.toml.example C:\ProgramData\Amazon\AmazonCloudWatchAgent\common-config.toml
notepad C:\ProgramData\Amazon\AmazonCloudWatchAgent\common-config.toml   # set your Windows user folder
& "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" -a fetch-config -m onPremise -s -c file:$HOME\Documents\SOC-\agent\amazon-cloudwatch-agent.json
& "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" -a status
```

## 6. Confirm logs arrive

```powershell
aws logs describe-log-streams --log-group-name /hsoc/windows/sysmon --query "logStreams[].[logStreamName,storedBytes]"
```
