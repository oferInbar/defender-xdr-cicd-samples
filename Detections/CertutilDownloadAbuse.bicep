targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'xdr-4a9d3c2e-7f1b-4e58-9a0c-2d5b8e3f1a7c'
  displayName: 'CertUtil Used for File Download (Living off the Land)'
  status: 'disabled'
  queryCondition: {
    queryText: '''
let Lookback = 1h;
let AllowlistedDomains = dynamic([
  "windowsupdate.microsoft.com",
  "download.microsoft.com",
  "dl.delivery.mp.microsoft.com",
  "ctldl.windowsupdate.com"
]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache", "-verifyctl", "-decode", "-decodehex")
| where ProcessCommandLine has_any ("http://", "https://", "ftp://")
| where not(ProcessCommandLine has_any (AllowlistedDomains))
| extend
    AccountName   = InitiatingProcessAccountName,
    AccountDomain = InitiatingProcessAccountDomain,
    HostName      = DeviceName,
    EventTime     = Timestamp
| project Timestamp, DeviceId, ReportId, EventTime, HostName, AccountName, AccountDomain,
    ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime desc
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'CertUtil Used for File Download (Living off the Land)'
      description: 'Detects certutil.exe being used to download files from remote URLs via the -urlcache or -verifyctl flags. CertUtil is a signed Windows binary (LOLBin) that attackers abuse to download payloads while bypassing application whitelisting and network controls. Tune AllowlistedDomains to match your PKI/CA infrastructure.'
      severity: 'high'
      tactics: [
        {
          tactic: 'CommandAndControl'
          techniques: [
            {
              technique: 'T1105'
            }
          ]
        }
        {
          tactic: 'DefenseEvasion'
          techniques: [
            {
              technique: 'T1218'
            }
            {
              technique: 'T1140'
            }
          ]
        }
      ]
      entityMappings: {
        hosts: [
          {
            id: 'host1'
            nameColumn: 'HostName'
          }
        ]
        accounts: [
          {
            id: 'account1'
            nameColumn: 'AccountName'
            ntDomainColumn: 'AccountDomain'
          }
        ]
      }
      customDetails: {
        HostFullName: 'HostName'
        ProcessCommandLine: 'ProcessCommandLine'
      }
    }
  }
}
