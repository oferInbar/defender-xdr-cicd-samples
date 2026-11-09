targetScope = 'managementGroup'
extension MicrosoftSecurity

resource workbook 'Microsoft.Security/workbooks@2026-06-01-preview' = {
  id: '200c5dd2-9786-5619-8425-4508a238d76a'
  name: 'Microsoft Defender For Identity'
  content: {
    version: 'Notebook/1.0'
    items: [
      {
        type: 1
        content: {
          json: '## Microsoft Defender for Identity\n---\n'
        }
        name: 'text - 2'
      }
      {
        type: 9
        content: {
          version: 'KqlParameterItem/1.0'
          parameters: [
            {
              id: '2e238f92-709c-410b-93e0-60eab6150a75'
              version: 'KqlParameterItem/1.0'
              name: 'TimeRange'
              type: 4
              isRequired: true
              value: {
                durationMs: 1800000
              }
              typeSettings: {
                selectableValues: [
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
              id: 'ec13514a-7e54-4d41-86db-2805727a2fa7'
              version: 'KqlParameterItem/1.0'
              name: 'About'
              type: 10
              description: ''
              isRequired: true
              value: 'Show'
              typeSettings: {
                additionalResourceOptions: []
                showDefault: false
              }
              jsonData: '[\r\n    "Show",\r\n    "Hide"\r\n]'
            }
          ]
          style: 'pills'
        }
        name: 'parameters - 1'
      }
      {
        type: 12
        content: {
          version: 'NotebookGroup/1.0'
          groupType: 'editable'
          items: [
            {
              type: 1
              content: {
                json: '### Microsoft Defender for Identity Analysis Workbook\r\n\r\n'
                style: 'info'
              }
              name: 'text - 0'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'About'
          comparison: 'isEqualTo'
          value: 'Show'
        }
        name: 'AboutGroup'
      }
      {
        type: 11
        content: {
          version: 'LinkItem/1.0'
          style: 'tabs'
          links: [
            {
              id: '48578fe1-da47-4a4c-b495-ce7fe24ce495'
              cellValue: 'Nav'
              linkTarget: 'parameter'
              linkLabel: 'Overview'
              subTarget: 'grpOverview'
              style: 'link'
            }
            {
              id: '30e93159-8bf5-4006-820f-406ea10bcd17'
              cellValue: 'Nav'
              linkTarget: 'parameter'
              linkLabel: 'LogOnEvents'
              subTarget: 'grpLogOnEvents'
              style: 'link'
            }
            {
              id: 'c40f76ed-94be-40ff-b65b-3fda306f2c3d'
              cellValue: 'Nav'
              linkTarget: 'parameter'
              linkLabel: 'QueryEvents'
              subTarget: 'grpQueryEvents'
              style: 'link'
            }
            {
              id: '38c88a53-f7b1-42da-83d6-0c809835eaab'
              cellValue: 'Nav'
              linkTarget: 'parameter'
              linkLabel: 'DirectoryEvents'
              subTarget: 'grpDirectoryEvents'
              style: 'link'
            }
            {
              id: '0ad83579-c492-4c20-8db6-27883db5abc8'
              cellValue: 'Nav'
              linkTarget: 'parameter'
              linkLabel: 'Alerts'
              subTarget: 'grpAlerts'
              style: 'link'
            }
          ]
        }
        name: 'links - 8'
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
IdentityLogonEvents
| summarize count() by LogonType
                '''
                size: 0
                title: 'Log On Summary'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'tiles'
                tileSettings: {
                  showBorder: false
                  titleContent: {
                    columnMatch: 'LogonType'
                    formatter: 1
                  }
                  leftContent: {
                    columnMatch: 'count_'
                    formatter: 12
                    formatOptions: {
                      palette: 'auto'
                    }
                    numberFormat: {
                      unit: 17
                      options: {
                        maximumSignificantDigits: 3
                        maximumFractionDigits: 2
                      }
                    }
                  }
                }
              }
              customWidth: '40'
              name: 'query - 0'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityLogonEvents
|summarize count() by ActionType
                '''
                size: 0
                title: 'Log On Status'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'piechart'
              }
              customWidth: '30'
              name: 'query - 1'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityLogonEvents
| summarize count() by Protocol = coalesce(Protocol, "Unknown")
                '''
                size: 0
                title: 'Log On Protocol'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'barchart'
              }
              customWidth: '30'
              name: 'query - 1 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityQueryEvents
| summarize count() by Protocol
                '''
                size: 0
                title: 'Query Summary'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'barchart'
              }
              customWidth: '30'
              name: 'query - 3'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityQueryEvents
| summarize count() by DestinationPort = coalesce(tostring(DestinationPort), "Unknown")
                '''
                size: 0
                title: 'Query Destination Port'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'piechart'
              }
              customWidth: '30'
              name: 'query - 3 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityQueryEvents
| where isnotempty(QueryType)
| summarize count() by QueryType
| order by count_ desc
| take 10
                '''
                size: 0
                title: 'Top 10 Query Types'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'count_'
                      formatter: 8
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                  ]
                }
              }
              customWidth: '30'
              name: 'query - 7'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityDirectoryEvents
| summarize count() by Protocol = coalesce(Protocol, "Unknown")
                '''
                size: 0
                title: 'Directory Events Protocol'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'categoricalbar'
              }
              customWidth: '40'
              name: 'query - 6'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityDirectoryEvents
| summarize count() by AccountDomain = coalesce(AccountDomain, "Unknown")
                '''
                size: 0
                title: 'Directory Events Account Domain'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'piechart'
              }
              customWidth: '30'
              name: 'query - 6 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityDirectoryEvents
| extend Account = coalesce(AccountUpn, iff(isnotempty(AccountName) and isnotempty(AccountDomain), strcat(AccountDomain, "\\", AccountName), AccountName), tostring(AdditionalFields["ACTOR.ACCOUNT"]), AccountSid)
| where isnotempty(Account)
| summarize count() by Account
| order by count_ desc 
| take 10
                '''
                size: 0
                title: 'Top 10 Accounts Activity'
                subtitle: 'Account UPN, domain/name, actor account, or SID, in that order.'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'table'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'count_'
                      formatter: 8
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                  ]
                  rowLimit: 10000
                  filter: true
                }
              }
              customWidth: '30'
              name: 'query - 6 - Copy - Copy'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'Nav'
          comparison: 'isEqualTo'
          value: 'grpOverview'
        }
        name: 'grpOverview'
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
IdentityLogonEvents
| extend AdditionalFields = todynamic(tostring(AdditionalFields)) 
| where LogonType == "Resource access"
| extend FROM_DEVICE_ = tostring(AdditionalFields.["FROM.DEVICE"])
| extend TO_DEVICE_ = tostring(AdditionalFields.["TO.DEVICE"])
| extend Count_ = toint(AdditionalFields.Count)
| summarize sum(Count_) by FROM_DEVICE_, TO_DEVICE_
| order by sum_Count_ desc
                '''
                size: 0
                title: 'Resource Access Summary in Devices'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'sum_Count_'
                      formatter: 8
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                  ]
                  rowLimit: 10000
                  filter: true
                }
              }
              customWidth: '45'
              name: 'query - 0'
              styleSettings: {
                margin: '5px'
                padding: '5px'
                showBorder: true
              }
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityLogonEvents
| extend AdditionalFields = todynamic(tostring(AdditionalFields)) 
| where LogonType == "Resource access"
| extend TargetComputerOperatingSystem_ = tostring(AdditionalFields.TargetComputerOperatingSystem)
| extend DestinationComputerOperatingSystem_ = tostring(AdditionalFields.DestinationComputerOperatingSystem)
| extend Count_ = toint(AdditionalFields.Count)
| summarize sum(Count_) by TargetComputerOperatingSystem_, DestinationComputerOperatingSystem_
| order by sum_Count_ desc
                '''
                size: 0
                title: 'Resource Access Summary in OS'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'sum_Count_'
                      formatter: 8
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                  ]
                  rowLimit: 10000
                  filter: true
                }
              }
              customWidth: '45'
              name: 'query - 0 - Copy'
              styleSettings: {
                margin: '5px'
                padding: '5px'
                showBorder: true
              }
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityLogonEvents
| extend AdditionalFields = todynamic(tostring(AdditionalFields)) 
| where LogonType == "Credentials validation"
| extend FROM_DEVICE = tostring(AdditionalFields.["FROM.DEVICE"])
| extend TO_DEVICE = tostring(AdditionalFields.["TO.DEVICE"])
| extend Count = toint(AdditionalFields.Count)
| summarize sum(Count) by FROM_DEVICE, TO_DEVICE
| order by sum_Count desc
                '''
                size: 0
                title: 'Credentials validation Summary in Devices'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'sum_Count'
                      formatter: 8
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                  ]
                  rowLimit: 10000
                  filter: true
                }
              }
              customWidth: '45'
              name: 'query - 0 - Copy'
              styleSettings: {
                margin: '5px'
                padding: '5px'
                showBorder: true
              }
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let data = IdentityLogonEvents
| extend AdditionalFields = todynamic(tostring(AdditionalFields)) 
| where LogonType == "Credentials validation"
| extend TO_DEVICE = tostring(AdditionalFields.["TO.DEVICE"])
| extend Count = toint(AdditionalFields.Count);
data
| summarize sum(Count) by  TO_DEVICE
| order by sum_Count desc
| join kind=inner
(
data
| make-series Trend = count() default = 0 on Timestamp from {TimeRange:start} to {TimeRange:end} step {TimeRange:grain} by TO_DEVICE
)
on $left.TO_DEVICE == $right.TO_DEVICE
                '''
                size: 0
                title: 'Credentials validation by Domain Controllers'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'sum_Count'
                      formatter: 8
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'TO_DEVICE1'
                      formatter: 5
                    }
                    {
                      columnMatch: 'Trend'
                      formatter: 10
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'TimeGenerated'
                      formatter: 5
                    }
                  ]
                  rowLimit: 10000
                  filter: true
                }
              }
              customWidth: '45'
              name: 'query - 0 - Copy - Copy'
              styleSettings: {
                margin: '5px'
                padding: '5px'
                showBorder: true
              }
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let data = IdentityLogonEvents
| extend Count = coalesce(toint(AdditionalFields.Count), 1);
data
| summarize LogonSuccess = sumif(Count,ActionType == "LogonSuccess"),LogonFailed= sumif(Count,ActionType == "LogonFailed") by AccountUpn
| join kind = inner
(
data
| make-series Trend = sum(Count) default = 0 on Timestamp from {TimeRange:start} to {TimeRange:end} step {TimeRange:grain} by AccountUpn
) on $left.AccountUpn == $right.AccountUpn
                '''
                size: 0
                title: 'Logon Summary by Users'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'LogonSuccess'
                      formatter: 8
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'LogonFailed'
                      formatter: 8
                      formatOptions: {
                        palette: 'redPurple'
                      }
                    }
                    {
                      columnMatch: 'AccountUpn1'
                      formatter: 5
                    }
                    {
                      columnMatch: 'Trend'
                      formatter: 9
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'TimeGenerated'
                      formatter: 5
                    }
                  ]
                  rowLimit: 10000
                  filter: true
                }
              }
              name: 'query - 0 - Copy - Copy'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'Nav'
          comparison: 'isEqualTo'
          value: 'grpLogOnEvents'
        }
        name: 'AttachmentGroup'
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
let data = IdentityQueryEvents
| extend TO_DEVICE = tostring(AdditionalFields.["TO.DEVICE"]);
data
| summarize count() by QueryType, TO_DEVICE
| join kind =inner 
(
data
| make-series Trend = count() default = 0 on Timestamp from {TimeRange:start} to {TimeRange:end} step {TimeRange:grain} by QueryType, TO_DEVICE
) on $left.QueryType == $right.QueryType and $left.TO_DEVICE== $right.TO_DEVICE
                '''
                size: 0
                title: 'Device Query Summary'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'TO_DEVICE'
                      formatter: 5
                    }
                    {
                      columnMatch: 'count_'
                      formatter: 8
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'QueryType1'
                      formatter: 5
                    }
                    {
                      columnMatch: 'TO_DEVICE1'
                      formatter: 5
                    }
                    {
                      columnMatch: 'Trend'
                      formatter: 21
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'TimeGenerated'
                      formatter: 5
                    }
                  ]
                  rowLimit: 10000
                  filter: true
                  hierarchySettings: {
                    treeType: 1
                    groupBy: [
                      'TO_DEVICE'
                    ]
                    expandTopLevel: true
                  }
                }
              }
              name: 'query - 0'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let data = IdentityQueryEvents;
data
| summarize count() by DeviceName
| join kind =inner 
(
data
| make-series Trend = count() default = 0 on Timestamp from {TimeRange:start} to {TimeRange:end} step {TimeRange:grain} by DeviceName
) on $left.DeviceName == $right.DeviceName
                '''
                size: 0
                title: 'Query Summary from Source Devices'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'DeviceName1'
                      formatter: 5
                    }
                    {
                      columnMatch: 'Trend'
                      formatter: 9
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'TimeGenerated'
                      formatter: 5
                    }
                  ]
                  rowLimit: 10000
                  filter: true
                }
              }
              name: 'query - 0 - Copy'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'Nav'
          comparison: 'isEqualTo'
          value: 'grpQueryEvents'
        }
        name: 'UrlGroup'
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
IdentityDirectoryEvents
| make-series Trend = count() default = 0 on Timestamp from {TimeRange:start} to {TimeRange:end} step {TimeRange:grain} by ActionType 
                '''
                size: 0
                title: 'Timeline on ActionType'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'timechart'
              }
              name: 'query - 0'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityDirectoryEvents
| summarize count() by ActionType 
| order by count_ desc
| take 10
                '''
                size: 0
                title: 'Top 10 Actions'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'categoricalbar'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'Trend'
                      formatter: 9
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'TimeGenerated'
                      formatter: 5
                    }
                  ]
                }
                tileSettings: {
                  showBorder: false
                  titleContent: {
                    columnMatch: 'DestinationPort'
                    formatter: 1
                  }
                  leftContent: {
                    columnMatch: 'count_'
                    formatter: 12
                    formatOptions: {
                      palette: 'auto'
                    }
                    numberFormat: {
                      unit: 17
                      options: {
                        maximumSignificantDigits: 3
                        maximumFractionDigits: 2
                      }
                    }
                  }
                }
              }
              name: 'query - 0 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
IdentityDirectoryEvents
| extend Account = coalesce(AccountUpn, iff(isnotempty(AccountName) and isnotempty(AccountDomain), strcat(AccountDomain, "\\", AccountName), AccountName), tostring(AdditionalFields["ACTOR.ACCOUNT"]), AccountSid)
| where isnotempty(Account)
| make-series Trend = count() default = 0 on Timestamp from {TimeRange:start} to {TimeRange:end} step {TimeRange:grain} by Account
                '''
                size: 0
                title: 'Account Trend on Directory Events'
                subtitle: 'Account UPN, domain/name, actor account, or SID, in that order.'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                visualization: 'table'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'Trend'
                      formatter: 9
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'TimeGenerated'
                      formatter: 5
                    }
                  ]
                  rowLimit: 10000
                  filter: true
                }
                tileSettings: {
                  showBorder: false
                  titleContent: {
                    columnMatch: 'DestinationPort'
                    formatter: 1
                  }
                  leftContent: {
                    columnMatch: 'count_'
                    formatter: 12
                    formatOptions: {
                      palette: 'auto'
                    }
                    numberFormat: {
                      unit: 17
                      options: {
                        maximumSignificantDigits: 3
                        maximumFractionDigits: 2
                      }
                    }
                  }
                }
              }
              name: 'query - 0 - Copy - Copy'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'Nav'
          comparison: 'isEqualTo'
          value: 'grpDirectoryEvents'
        }
        name: 'group - 8'
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
let data = AlertInfo
| where ServiceSource == "Microsoft Defender for Identity"
| summarize arg_max(Timestamp, *) by AlertId;
data
| summarize count() by AlertName = Title
| join kind=inner 
(
data
| make-series Trend = count() default = 0 on Timestamp from {TimeRange:start} to {TimeRange:end} step {TimeRange:grain} by AlertName = Title
) on AlertName
                '''
                size: 0
                title: 'Alerts'
                noDataMessage: 'No identity alerts found in the selected time range.'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'count_'
                      formatter: 8
                      formatOptions: {
                        palette: 'red'
                      }
                    }
                    {
                      columnMatch: 'AlertName1'
                      formatter: 5
                    }
                    {
                      columnMatch: 'Trend'
                      formatter: 21
                      formatOptions: {
                        palette: 'red'
                      }
                    }
                    {
                      columnMatch: 'TimeGenerated'
                      formatter: 5
                    }
                  ]
                }
              }
              name: 'query - 0'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let data = AlertInfo
| where ServiceSource == "Microsoft Defender for Identity"
| join kind=inner AlertEvidence on AlertId
| where EntityType == "Machine" and isnotempty(DeviceName)
| summarize arg_max(Timestamp, *) by AlertId, DeviceName;
data
| summarize count() by HostName = DeviceName
| join kind=inner 
(
data
| make-series Trend = count() default = 0 on Timestamp from {TimeRange:start} to {TimeRange:end} step {TimeRange:grain} by HostName = DeviceName
) on $left.HostName == $right.HostName
                '''
                size: 0
                title: 'Impacted Hosts'
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'count_'
                      formatter: 8
                      formatOptions: {
                        palette: 'red'
                      }
                    }
                    {
                      columnMatch: 'HostName1'
                      formatter: 5
                    }
                    {
                      columnMatch: 'Trend'
                      formatter: 9
                      formatOptions: {
                        palette: 'red'
                      }
                    }
                    {
                      columnMatch: 'TimeGenerated'
                      formatter: 5
                    }
                  ]
                }
              }
              name: 'query - 1'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'Nav'
          comparison: 'isEqualTo'
          value: 'grpAlerts'
        }
        name: 'group - 8'
      }
    ]
  }
}
