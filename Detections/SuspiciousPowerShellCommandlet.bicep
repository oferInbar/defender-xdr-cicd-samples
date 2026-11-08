targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'xdr-b5153fb3-ada9-4ce4-9131-79c771efb50d'
  displayName: 'Suspicious Powershell Commandlet Executed'
  status: 'disabled'
  queryCondition: {
    queryText: '''
// Adjust the list of suspicious commandlets as needed
let SuspiciousPowerShellCommandList = dynamic(["Get-ADUserResultantPasswordPolicy",
  "Get-DomainPolicy",
  "Get-DomainUser",
  "Get-DomainComputer",
  "Get-DomainController",
  "Get-DomainGroup",
  "Get-DomainTrust",
  "Get-ADTrust",
  "Get-ForestTrust"
  ]);
DeviceEvents
| where ActionType == "PowerShellCommand"
| extend Commandlet = tostring(parse_json(AdditionalFields).Command)
| where Commandlet has_any (SuspiciousPowerShellCommandList)
| project Timestamp, DeviceId, ReportId, DeviceName, LocalIP, InitiatingProcessAccountUpn, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| extend Username = tostring(split(InitiatingProcessAccountUpn, '@')[0]), UPNSuffix = tostring(split(InitiatingProcessAccountUpn, '@')[1])
| extend DvcHostname = tostring(split(DeviceName, '.')[0]), DvcDomain = tostring(strcat_array(array_slice(split(DeviceName, '.'), 1, -1), '.'))
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Suspicious Powershell Commandlet Executed'
      description: 'This analytic rule detects when a suspicious PowerShell commandlet is executed on a host. Threat actors often use PowerShell to execute commands and scripts to move laterally, escalate privileges, and exfiltrate data.'
      severity: 'medium'
      tactics: [
        {
          tactic: 'Execution'
          techniques: [
            {
              technique: 'T1059'
            }
          ]
        }
      ]
      entityMappings: {
        hosts: [
          {
            id: 'host1'
            nameColumn: 'DvcHostname'
            dnsDomainColumn: 'DvcDomain'
          }
        ]
        ips: [
          {
            id: 'ip1'
            addressColumn: 'LocalIP'
          }
        ]
        accounts: [
          {
            id: 'account1'
            nameColumn: 'Username'
            upnSuffixColumn: 'UPNSuffix'
          }
        ]
      }
      customDetails: {
        HostFullName: 'DeviceName'
        ProcessProcessId: 'InitiatingProcessId'
        ProcessCommandLine: 'InitiatingProcessCommandLine'
      }
    }
  }
}
