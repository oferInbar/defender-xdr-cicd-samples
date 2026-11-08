targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'xdr-7b2f4d1a-9c3e-4f72-8b1d-3e6a9f2c4b8d'
  displayName: 'PowerShell Encoded Command Execution (Living off the Land)'
  status: 'disabled'
  queryCondition: {
    queryText: '''
let Lookback = 1h;
let EncodedFlagRegex = @'(?i)(^|\s)-(encodedcommand|enco|enc|ec|e)\b';
let EncodedValueRegex = @'(?i)(^|\s)-(encodedcommand|enco|enc|ec|e)\b\s?([^\s]+)';
let AllowlistedParents = dynamic([
  "SqlServer.exe", "ManagementStudio.exe", "devenv.exe",
  "ccmexec.exe", "SMSAgent.exe"
]);
let DownloadCradlePatterns = dynamic([
  "Net.WebClient", "WebRequest", "DownloadString", "DownloadFile",
  "IEX", "Invoke-Expression", "Invoke-RestMethod", "Start-BitsTransfer"
]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex EncodedFlagRegex
| where not(InitiatingProcessFileName has_any (AllowlistedParents))
| extend EncodedCommand = extract(EncodedValueRegex, 3, ProcessCommandLine)
| extend DecodedCommand = replace_string(
    base64_decode_tostring(EncodedCommand), '\0', ''
  )
| extend
    HasDownloadCradle = DecodedCommand has_any (DownloadCradlePatterns),
    AccountName = InitiatingProcessAccountName,
    AccountDomain = InitiatingProcessAccountDomain,
    HostName = DeviceName,
    EventTime = Timestamp
| extend RiskScore = iif(HasDownloadCradle, 2, 1)
| project Timestamp, DeviceId, ReportId, EventTime, HostName, AccountName, AccountDomain,
    ProcessCommandLine, DecodedCommand, InitiatingProcessFileName,
    HasDownloadCradle, RiskScore
| sort by RiskScore desc, EventTime desc
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'PowerShell Encoded Command Execution (Living off the Land)'
      description: 'Detects PowerShell or pwsh.exe launched with encoded command flags (-EncodedCommand, -enc, -ec, -enco). Attackers encode commands in Base64 to obfuscate malicious payloads and bypass script-based controls. Risk is elevated when a download cradle pattern is also detected. Tune AllowlistedParents for known-safe management tools such as SCCM.'
      severity: 'medium'
      tactics: [
        {
          tactic: 'Execution'
          techniques: [
            {
              technique: 'T1059'
              subTechniques: [
                'T1059.001'
              ]
            }
          ]
        }
        {
          tactic: 'DefenseEvasion'
          techniques: [
            {
              technique: 'T1027'
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
