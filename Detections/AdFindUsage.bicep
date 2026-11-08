targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'xdr-c63ae777-d5e0-4113-8c9a-c2c9d3d09fcd'
  displayName: 'Probable AdFind Recon Tool Usage'
  status: 'disabled'
  queryCondition: {
    queryText: '''
let args = dynamic(["objectcategory","domainlist","dcmodes","adinfo","trustdmp","computers_pwdnotreqd","Domain Admins", "objectcategory=person", "objectcategory=computer", "objectcategory=*","dclist"]);
let parentProcesses = dynamic(["pwsh.exe","powershell.exe","cmd.exe"]);
DeviceProcessEvents
//looks for execution from a shell
| where InitiatingProcessFileName in~ (parentProcesses)
// main filter
| where FileName =~ "AdFind.exe" or SHA256 == "c92c158d7c37fea795114fa6491fe5f145ad2f8c08776b18ae79db811e8e36a3"
   // AdFind common Flags to check for from various threat actor TTPs
    or ProcessCommandLine has_any (args)
| extend HostName = tostring(split(DeviceName, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(DeviceName, '.'), 1, -1), '.')), FileHashAlgorithm = "SHA256"
| project Timestamp, DeviceId, ReportId, DeviceName, HostName, DnsDomain, AccountName, AccountDomain, InitiatingProcessFileName, ProcessCommandLine, FileHashAlgorithm, SHA256
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Probable AdFind Recon Tool Usage'
      description: 'This query identifies the host and account that executed AdFind, by hash and filename, in addition to the flags commonly utilized by various threat actors during the reconnaissance phase.'
      severity: 'high'
      tactics: [
        {
          tactic: 'Discovery'
          techniques: [
            {
              technique: 'T1016'
            }
            {
              technique: 'T1018'
            }
            {
              technique: 'T1069'
              subTechniques: [
                'T1069.002'
              ]
            }
            {
              technique: 'T1087'
              subTechniques: [
                'T1087.002'
              ]
            }
            {
              technique: 'T1482'
            }
          ]
        }
      ]
      entityMappings: {
        accounts: [
          {
            id: 'account1'
            nameColumn: 'AccountName'
            upnSuffixColumn: 'AccountDomain'
          }
        ]
        hosts: [
          {
            id: 'host1'
            nameColumn: 'HostName'
            dnsDomainColumn: 'DnsDomain'
          }
        ]
      }
      customDetails: {
        ProcessProcessId: 'InitiatingProcessFileName'
        ProcessCommandLine: 'ProcessCommandLine'
        FileHashAlgorithm: 'FileHashAlgorithm'
        FileHashValue: 'SHA256'
      }
    }
  }
}
