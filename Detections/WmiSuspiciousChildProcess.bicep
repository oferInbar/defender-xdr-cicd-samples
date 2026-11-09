targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'xdr-3c8e5f0b-1d4a-4b69-9c2e-7f0d3a5e8b1f'
  displayName: 'WMI Spawning Suspicious Child Process (Living off the Land)'
  status: 'disabled'
  queryCondition: {
    queryText: '''
let Lookback = 1h;
let SuspiciousChildProcesses = dynamic([
  "powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe",
  "mshta.exe", "certutil.exe", "bitsadmin.exe", "regsvr32.exe",
  "rundll32.exe", "msiexec.exe", "installutil.exe", "cmstp.exe",
  "msbuild.exe", "wmic.exe", "net.exe", "net1.exe", "nltest.exe",
  "whoami.exe", "ipconfig.exe", "tasklist.exe", "schtasks.exe",
  "at.exe", "sc.exe", "reg.exe"
]);
let AllowlistedCmdPatterns = dynamic([
  "ccmexec", "SMSAgent", "MOMAgent", "nessus", "qualys"
]);
let NetworkIndicators = dynamic([
  "http://", "https://", "ftp://", "Net.WebClient",
  "DownloadString", "IEX", "Invoke-Expression", "/transfer", "-urlcache"
]);
let CredentialIndicators = dynamic([
  "lsass", "mimikatz", "sekurlsa", "dump", "sam", "ntds"
]);
DeviceProcessEvents
| where Timestamp >= ago(Lookback)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ (SuspiciousChildProcesses)
| where not(ProcessCommandLine has_any (AllowlistedCmdPatterns))
| extend
    ChildProcess       = FileName,
    ChildCmdLine       = ProcessCommandLine,
    AccountName        = InitiatingProcessAccountName,
    AccountDomain      = InitiatingProcessAccountDomain,
    HostName           = DeviceName,
    EventTime          = Timestamp,
    NetworkActivity    = ProcessCommandLine has_any (NetworkIndicators),
    CredentialActivity = ProcessCommandLine has_any (CredentialIndicators)
| extend RiskScore = iif(CredentialActivity == true, 3, iif(NetworkActivity == true, 2, 1))
| project Timestamp, DeviceId, ReportId, EventTime, HostName, AccountName, AccountDomain, ChildProcess,
    ChildCmdLine, NetworkActivity, CredentialActivity, RiskScore
| sort by RiskScore desc, EventTime desc
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'WMI Spawning Suspicious Child Process (Living off the Land)'
      description: 'Detects WmiPrvSE.exe (the WMI Provider Host) spawning high-risk processes such as PowerShell, cmd.exe, cscript, or other LOLBins. WMI requires no external tools, generates minimal disk artifacts, and can execute code on remote systems over DCOM/RPC while bypassing many controls. Tune AllowlistedCmdPatterns for known-safe management tools such as SCCM.'
      severity: 'high'
      tactics: [
        {
          tactic: 'Execution'
          techniques: [
            {
              technique: 'T1047'
            }
            {
              technique: 'T1059'
              subTechniques: [
                'T1059.001'
                'T1059.003'
                'T1059.005'
              ]
            }
          ]
        }
        {
          tactic: 'LateralMovement'
          techniques: [
            {
              technique: 'T1021'
              subTechniques: [
                'T1021.006'
              ]
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
        ProcessCommandLine: 'ChildCmdLine'
      }
    }
  }
}
