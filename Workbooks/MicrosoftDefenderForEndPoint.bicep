targetScope = 'managementGroup'
extension MicrosoftSecurity

resource workbook 'Microsoft.Security/workbooks@2026-06-01-preview' = {
  id: '05a7425a-fcda-5e24-823d-f8c9dd7a6215'
  name: 'Microsoft Defender For EndPoint'
  content: {
    version: 'Notebook/1.0'
    items: [
      {
        type: 1
        content: {
          json: '## Microsoft Defender for Endpoint (Preview)\n---\n\nA workbook to provide details about Microsoft Defender for Endpoint Advance Hunting to Overview & Analyse data brought through Microsoft Defender XDR Connector.\n\n\n'
        }
        name: 'text - 2'
      }
      {
        type: 9
        content: {
          version: 'KqlParameterItem/1.0'
          parameters: [
            {
              id: 'b22a3bd7-19b3-495d-a0df-95a7a59d98ff'
              version: 'KqlParameterItem/1.0'
              name: 'TimeRange'
              type: 4
              value: {
                durationMs: 172800000
              }
              typeSettings: {
                selectableValues: [
                  {
                    durationMs: 300000
                  }
                  {
                    durationMs: 900000
                  }
                  {
                    durationMs: 1800000
                  }
                  {
                    durationMs: 3600000
                  }
                  {
                    durationMs: 14400000
                  }
                  {
                    durationMs: 43200000
                  }
                  {
                    durationMs: 86400000
                  }
                  {
                    durationMs: 172800000
                  }
                  {
                    durationMs: 259200000
                  }
                  {
                    durationMs: 604800000
                  }
                  {
                    durationMs: 1209600000
                  }
                  {
                    durationMs: 2419200000
                  }
                  {
                    durationMs: 2592000000
                  }
                  {
                    durationMs: 5184000000
                  }
                  {
                    durationMs: 7776000000
                  }
                ]
                allowCustom: true
              }
              timeContext: {
                durationMs: 86400000
              }
            }
            {
              id: 'f0450560-ef16-4aa9-a3ad-7485dd909587'
              version: 'KqlParameterItem/1.0'
              name: 'Help'
              type: 10
              isRequired: true
              typeSettings: {
                additionalResourceOptions: []
              }
              jsonData: '[{ "value": "Yes", "label": "Yes"},\r\n {"value": "No", "label": "No", "selected":true }]'
              label: 'Show Help'
              value: 'Yes'
            }
          ]
          style: 'pills'
        }
        name: 'parameters - 2'
      }
      {
        type: 1
        content: {
          json: '\r\n|Overview|Device|Network|File|\r\n|--------|------|-------|----|\r\n|MDE Tables Last Data Received|Source of the AV detections|Internet Connected Devices|FileActivityCount per Device|\r\n|Daily Data Flow on MDE Tables|Get stats on ASR audit events|Count By Machine Group|Count by InitiatingProcessAccountUpn|\r\n|Device Heartbeat|Get stats on ASR blocks|Count By Network Adaptor||\r\n|Device where files are copied to USB Drive|AV Detections with USB Disk Drive|TimeSeries on Network Activity||\r\n|Device Internet Connectivity Status |List files copied to USB mounted drives|Top 10 RemoteUrl accessed over TimeRange||\r\n|Device Count by DNS Suffix ||Tor Clients||\r\n|Device Microsoft Entra ID Join status ||||\r\n|Device ClientVersion ||||'
        }
        conditionalVisibility: {
          parameterName: 'Help'
          comparison: 'isEqualTo'
          value: 'Yes'
        }
        name: 'text - 8'
      }
      {
        type: 11
        content: {
          version: 'LinkItem/1.0'
          style: 'tabs'
          links: [
            {
              id: '454d4e02-26ba-4195-ae30-94752bbf4603'
              cellValue: 'selectedTab'
              linkTarget: 'parameter'
              linkLabel: 'Overview'
              subTarget: 'Overview'
              preText: 'Overview'
              style: 'link'
            }
            {
              id: '3d902e84-3e5b-4631-85d1-c229ec2abf75'
              cellValue: 'selectedTab'
              linkTarget: 'parameter'
              linkLabel: 'Device'
              subTarget: 'Device'
              style: 'link'
            }
            {
              id: 'bbc20288-b398-4f63-b7a9-e3830213bb34'
              cellValue: 'selectedTab'
              linkTarget: 'parameter'
              linkLabel: 'Network'
              subTarget: 'Network'
              style: 'link'
            }
            {
              id: 'edab4a44-8ca3-4ba1-bede-4186f4376d28'
              cellValue: 'selectedTab'
              linkTarget: 'parameter'
              linkLabel: 'File'
              subTarget: 'File'
              style: 'link'
            }
          ]
        }
        name: 'links - 3'
      }
      {
        type: 12
        content: {
          version: 'NotebookGroup/1.0'
          groupType: 'editable'
          items: [
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
union 
isfuzzy = true
(DeviceInfo | summarize arg_max(Timestamp,*) | project Timestamp, Type= "DeviceInfo" | extend Description = "Machine information (including OS information)"),
(DeviceNetworkInfo | summarize arg_max(Timestamp,*) | project Timestamp, Type="DeviceNetworkInfo"  | extend Description = "Network properties of machines"),
(DeviceProcessEvents | summarize arg_max(Timestamp,*) | project Timestamp, Type="DeviceProcessEvents" | extend Description = "Process creation and related events"),
(DeviceNetworkEvents | summarize arg_max(Timestamp,*) | project Timestamp, Type="DeviceNetworkEvents" | extend Description = "Network connection and related events"),
(DeviceFileEvents | summarize arg_max(Timestamp,*) | project Timestamp, Type="DeviceFileEvents" | extend Description = "File creation, modification, and other file system events"),
(DeviceRegistryEvents | summarize arg_max(Timestamp,*) | project Timestamp, Type="DeviceRegistryEvents" | extend Description = "Creation and modification of registry entries"),
(DeviceLogonEvents | summarize arg_max(Timestamp,*) | project Timestamp, Type="DeviceLogonEvents" | extend Description = "Sign-ins and other authentication events"),
(DeviceImageLoadEvents | summarize arg_max(Timestamp,*) | project Timestamp, Type="DeviceImageLoadEvents" | extend Description = "DLL loading events"),
(DeviceEvents | summarize arg_max(Timestamp,*) | project Timestamp, Type="DeviceEvents" | extend Description = "Additional events types"),
(DeviceFileCertificateInfo | summarize arg_max(Timestamp,*) | project Timestamp, Type="DeviceFileCertificateInfo" | extend Description = "Certificate information of signed files)")
| extend ["Last Log Received At (Local Time)"] = Timestamp
| project Type, Description, ["Last Log Received At (Local Time)"]
                '''
                size: 0
                title: 'MDE Tables Last Data Received based on {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'table'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'Type'
                      formatter: 0
                      numberFormat: {
                        unit: 0
                        options: {
                          style: 'decimal'
                        }
                      }
                    }
                    {
                      columnMatch: 'Last Log Received At'
                      formatter: 6
                      dateFormat: {
                        showUtcTime: null
                        formatName: 'fullDateTimePattern'
                      }
                    }
                  ]
                  filter: true
                }
              }
              name: 'query - 9'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let AllDeviceNames = DeviceInfo | distinct DeviceId, DeviceName;
let DeviceEventSummary = DeviceEvents | extend Type = "DeviceEvents" | summarize count() by DeviceId, Type, bin(Timestamp,1d);
let DeviceNetworkEventsSummary = DeviceNetworkEvents | extend Type = "DeviceNetworkEvents" | summarize count() by DeviceId,Type, bin(Timestamp,1d);
let DeviceNetworkInfoSummary = DeviceNetworkInfo | extend Type = "DeviceNetworkInfo" | summarize count() by DeviceId,Type, bin(Timestamp,1d);
let DeviceLogonEventsSummary = DeviceLogonEvents | extend Type = "DeviceLogonEvents" | summarize count() by DeviceId,Type, bin(Timestamp,1d);
let DeviceRegistryEventsSummary = DeviceRegistryEvents | extend Type = "DeviceRegistryEvents" | summarize count() by DeviceId,Type, bin(Timestamp,1d);
let DeviceProcessEventsSummary = DeviceProcessEvents | extend Type = "DeviceProcessEvents" | summarize count() by DeviceId,Type, bin(Timestamp,1d);
(DeviceEventSummary
| union DeviceNetworkEventsSummary,
DeviceNetworkInfoSummary,
DeviceLogonEventsSummary,
DeviceRegistryEventsSummary,
DeviceProcessEventsSummary)
| join kind=inner ( 
AllDeviceNames
)
on $left.DeviceId == $right.DeviceId
| project-reorder Type, Timestamp, count_
//| project-away DeviceId, DeviceId1
                '''
                size: 1
                title: 'Daily Data Flow on MDE Tables over {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'timechart'
                chartSettings: {
                  xAxis: 'TimeGenerated'
                  yAxis: [
                    'count_'
                  ]
                  splitBy: [
                    'Type'
                  ]
                }
              }
              name: 'query - 2'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceInfo 
| summarize arg_max(Timestamp,*) by DeviceId
| extend ParsedFields=parse_json(LoggedOnUsers)[0]
| extend DurationAtLeast= format_timespan(now()-Timestamp,'dd:hh:mm:ss')
| project DurationAtLeast,Timestamp,DeviceName,DomainName=ParsedFields.DomainName,UserName=ParsedFields.UserName
| order by DurationAtLeast asc
                '''
                size: 0
                title: 'Device Heartbeat from TimeTange {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  filter: true
                }
              }
              name: 'query - 0'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let UsbDriveMount = DeviceEvents
| where ActionType=="UsbDriveMounted"
| extend ParsedFields=parse_json(AdditionalFields)
| project DeviceId, DeviceName, DriveLetter=ParsedFields.DriveLetter, MountTime=Timestamp,
ProductName=ParsedFields.ProductName,SerialNumber=ParsedFields.SerialNumber,Manufacturer=ParsedFields.Manufacturer
| order by DeviceId asc, MountTime desc;
let FileCreation = DeviceFileEvents
| where InitiatingProcessAccountName != "system"
| where ActionType == "FileCreated"
| where FolderPath !startswith "C:\\"
| where FolderPath !startswith "\\"
| project ReportId,DeviceId,InitiatingProcessAccountDomain,
InitiatingProcessAccountName,InitiatingProcessAccountUpn,
FileName, FolderPath, SHA256, Timestamp, SensitivityLabel, IsAzureInfoProtectionApplied
| order by DeviceId asc, Timestamp desc;
FileCreation | lookup kind=inner (UsbDriveMount) on DeviceId
| where FolderPath startswith DriveLetter
| where Timestamp >= MountTime
| partition by ReportId ( top 1 by MountTime )
| order by DeviceId asc, Timestamp desc
| summarize FileCount = count() by DeviceName
| order by FileCount desc
                '''
                size: 1
                title: 'Device where files are copied to USB Drive from TimeTange {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'FileCount'
                      formatter: 8
                      formatOptions: {
                        palette: 'red'
                      }
                    }
                  ]
                  filter: true
                }
              }
              customWidth: '50'
              name: 'query - 0 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceNetworkInfo
| extend ConnectedNetworks = todynamic(tostring(ConnectedNetworks)) 
| summarize arg_max(Timestamp,*) by DeviceId
| mvexpand ConnectedNetworks
| summarize count() by InternetConnectivity = coalesce(tostring(ConnectedNetworks.IsConnectedToInternet), "Unknown")
                '''
                size: 1
                title: 'Device Internet Connectivity Status from TimeTange {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'piechart'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'FileCount'
                      formatter: 8
                      formatOptions: {
                        palette: 'red'
                      }
                    }
                  ]
                  filter: true
                }
              }
              customWidth: '50'
              name: 'query - 0 - Copy - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceInfo
| where isnotempty(OSPlatform)
| summarize arg_max(Timestamp, DeviceName) by DeviceId
| extend DeviceMachineName = split(DeviceName, '.')[0]
| extend DeviceDomain = substring(DeviceName, strlen(DeviceMachineName) + 1, strlen(DeviceName) - strlen(DeviceMachineName) - 1)
| summarize count() by DeviceDomain = coalesce(DeviceDomain, "No DNS suffix")
                '''
                size: 1
                title: 'Device Count by DNS Suffix'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'piechart'
                gridSettings: {
                  filter: true
                }
                chartSettings: {
                  showMetrics: false
                  showLegend: true
                }
              }
              customWidth: '30'
              name: 'query - 0 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceInfo
| where isnotempty(OSPlatform)
| summarize arg_max(Timestamp, *) by DeviceId
| summarize count() by EntraIDJoinStatus = coalesce(tostring(IsAzureADJoined), "Unknown")
                '''
                size: 1
                title: 'Device EntraID Join status'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'piechart'
                gridSettings: {
                  filter: true
                }
                chartSettings: {
                  showMetrics: false
                  showLegend: true
                }
              }
              customWidth: '30'
              name: 'query - 0 - Copy - Copy - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceInfo
| where isnotempty(OSPlatform)
| summarize arg_max(Timestamp, *) by DeviceId
| summarize count() by ClientVersion
                '''
                size: 1
                title: 'Device ClientVersion'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'piechart'
                gridSettings: {
                  filter: true
                }
                chartSettings: {
                  showMetrics: false
                  showLegend: true
                }
              }
              customWidth: '30'
              name: 'query - 0 - Copy - Copy - Copy - Copy'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'selectedTab'
          comparison: 'isEqualTo'
          value: 'Overview'
        }
        name: 'groupOverview'
      }
      {
        type: 12
        content: {
          version: 'NotebookGroup/1.0'
          groupType: 'editable'
          items: [
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
//This query shows the source of the AV detections (e.g., the website the file was downloaded from etc.)
//
//Get the list of AV detections
let avDetections =
DeviceEvents
| where ActionType == "AntivirusDetection" and isnotempty(MD5)
| extend ParsedFields=parse_json(AdditionalFields)
| project Timestamp, DeviceName, ThreatName=tostring(ParsedFields.ThreatName), FileName, FolderPath, MD5;
//Get a list of file creations
let fileCreations =
DeviceFileEvents 
| where (isnotempty(FileOriginReferrerUrl) or isnotempty(FileOriginUrl)) and isnotempty(MD5)
| project MD5, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessFileName, InitiatingProcessParentFileName;
//Join the file creations and AV detections on the MD5 of the file
avDetections | join kind=inner (fileCreations) on MD5
| project-away MD51 //Remove the duplicated MD5 field
| sort by Timestamp desc 
                '''
                size: 0
                title: 'Source of the AV detections for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  filter: true
                }
              }
              name: 'query - 0'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceEvents
| where ActionType startswith "Asr" and ActionType endswith "Audited"
// Count total stats - count events and machines per rule
| summarize EventCount=count(), MachinesCount=dcount(DeviceId) by ActionType
                '''
                size: 0
                title: 'Get stats on ASR audit events - count events and machines per rule for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
              }
              name: 'query - 1'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceEvents
| where ActionType startswith "Asr" and ActionType endswith "Blocked"
// Count total stats - count events and machines per rule
| summarize EventCount=count(), MachinesCount=dcount(DeviceId) by ActionType
                '''
                size: 0
                title: 'Get stats on ASR blocks - count events and machines per rule for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
              }
              name: 'query - 1 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
//This query make a best-guess detection regarding which removable media device caused an AV detection
//The query is best run over 30 days to get the full USB history
//
//Get a list of USB AV detections. This assumes any path not beginning with C is a removable/USB device
let usbDetections =
    DeviceEvents
    | where ActionType == "AntivirusDetection" and FolderPath !startswith "c" and FolderPath matches regex "^[A-Za-z]{1}"
    | extend ParsedFields=parse_json(AdditionalFields)
    | project DetectionTime=Timestamp, DeviceName, ThreatName=tostring(ParsedFields.ThreatName), FileName, FolderPath;
//Get a list of USB disk drive connections, grouped by computer name and DeviceID
let usbConnections = 
    DeviceEvents
    | where ActionType == "PnpDeviceConnected"
    | extend parsed=parse_json(AdditionalFields)
    | project Timestamp, DeviceName, DeviceId=tostring(parsed.DeviceId), ClassName=tostring(parsed.ClassName)
    | where ClassName == "DiskDrive"
    | summarize UsbFirstSeen=min(Timestamp), UsbLastSeen=max(Timestamp) by DeviceId, DeviceName;
//Join USB AV detections and connections, where the detection occurs after the USB has been plugged in
usbDetections | join kind=inner (usbConnections) on DeviceName | where DetectionTime > UsbFirstSeen and DetectionTime < UsbLastSeen
| project DetectionTime, DeviceName, ThreatName, FileName, FolderPath, DeviceId, UsbFirstSeen, UsbLastSeen
| sort by DetectionTime desc
                '''
                size: 0
                title: 'AV Detections with USB Disk Drive for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
              }
              name: 'query - 3'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let UsbDriveMount = DeviceEvents
| where ActionType=="UsbDriveMounted"
| extend ParsedFields=parse_json(AdditionalFields)
| project DeviceId, DeviceName, DriveLetter=ParsedFields.DriveLetter, MountTime=Timestamp,
ProductName=ParsedFields.ProductName,SerialNumber=ParsedFields.SerialNumber,Manufacturer=ParsedFields.Manufacturer
| order by DeviceId asc, MountTime desc;
let FileCreation = DeviceFileEvents
| where InitiatingProcessAccountName != "system"
| where ActionType == "FileCreated"
| where FolderPath !startswith "C:\\"
| where FolderPath !startswith "\\"
| project ReportId,DeviceId,InitiatingProcessAccountDomain,
InitiatingProcessAccountName,InitiatingProcessAccountUpn,
FileName, FolderPath, SHA256, Timestamp, SensitivityLabel, IsAzureInfoProtectionApplied
| order by DeviceId asc, Timestamp desc;
FileCreation | lookup kind=inner (UsbDriveMount) on DeviceId
| where FolderPath startswith DriveLetter
| where Timestamp >= MountTime
| partition by ReportId ( top 1 by MountTime )
| order by DeviceId asc, Timestamp desc
                '''
                size: 0
                title: 'List files copied to USB mounted drives for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
              }
              name: 'query - 4'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'selectedTab'
          comparison: 'isEqualTo'
          value: 'Device'
        }
        name: 'groupDevice'
      }
      {
        type: 12
        content: {
          version: 'NotebookGroup/1.0'
          groupType: 'editable'
          items: [
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceNetworkInfo
| extend ConnectedNetworks = todynamic(tostring(ConnectedNetworks)) 
| summarize arg_max(Timestamp,*) by DeviceId
| mv-apply ConnectedNetworks on 
(
where ConnectedNetworks.IsConnectedToInternet == true
)
| project DeviceName, DefaultGateways, IPv4Dhcp, IPv6Dhcp,MacAddress,MachineGroup, ConnectedNetworks.IsConnectedToInternet
                '''
                size: 0
                title: 'Internet Connected Devices for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
              }
              name: 'query - 0'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceNetworkInfo
| summarize arg_max(Timestamp,*) by DeviceId
| summarize count() by MachineGroup
                '''
                size: 0
                title: 'Count By Machine Group for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  filter: true
                }
              }
              name: 'query - 0 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceNetworkInfo
| summarize arg_max(Timestamp,*) by DeviceId
| summarize count() by NetworkAdapterType, NetworkAdapterStatus
                '''
                size: 0
                title: 'Count By Network Adaptor'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  filter: true
                }
              }
              name: 'query - 0 - Copy - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceNetworkEvents
| summarize count() by DeviceName, DeviceId,bin( Timestamp,5m)
                '''
                size: 0
                title: 'TimeSeries on Network Activity for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'timechart'
              }
              name: 'query - 0 - Copy - Copy - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| summarize count() by RemoteUrl
| order by count_ desc
| limit 10
                '''
                size: 0
                title: 'Top 10 RemoteUrl accessed over TimeRange {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'categoricalbar'
              }
              name: 'query - 0 - Copy - Copy - Copy - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
// This query looks for Tor client, or for a common Tor plugin called Meek.
// We query for active Tor connections, but could have alternatively looked for active Tor runs (ProcessCreateEvents) or Tor downloads (DeviceFileEvents)
// To read more about this technique, see:
// Tor: https://attack.mitre.org/wiki/Software/S0183#Techniques_Used
// Meek plugin: https://attack.mitre.org/wiki/Software/S0175
// Multi-hop proxy technique: https://attack.mitre.org/wiki/Technique/T1188
// Tags: #Tor, #MultiHopProxy, #CnC
DeviceNetworkEvents  
| where InitiatingProcessFileName in~ ("tor.exe", "meek-client.exe")
// Returns MD5 hashes of files used by Tor, to enable you to block them.
// We count how prevalent each file is (by machines) and show examples for some of them (up to 5 machine names per hash).
| summarize MachineCount=dcount(DeviceName), MachineNames=makeset(DeviceName, 5) by InitiatingProcessMD5
| order by MachineCount desc
                '''
                size: 0
                title: 'Tor Clients for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
              }
              name: 'query - 5'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'selectedTab'
          comparison: 'isEqualTo'
          value: 'Network'
        }
        name: 'groupNetwork'
      }
      {
        type: 12
        content: {
          version: 'NotebookGroup/1.0'
          groupType: 'editable'
          items: [
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceFileEvents
| summarize FileActivityCount = count() by DeviceName
                '''
                size: 0
                title: 'FileActivityCount per Device for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'unstackedbar'
              }
              name: 'query - 0'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
DeviceFileEvents
| summarize count() by InitiatingProcessAccountUpn = coalesce(InitiatingProcessAccountUpn, "No UPN")
                '''
                size: 0
                title: 'Count by InitiatingProcessAccountUpn for {TimeRange}'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'unstackedbar'
              }
              name: 'query - 0 - Copy'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'selectedTab'
          comparison: 'isEqualTo'
          value: 'File'
        }
        name: 'groupFile'
      }
    ]
  }
}
