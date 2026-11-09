targetScope = 'managementGroup'
extension MicrosoftSecurity

resource workbook 'Microsoft.Security/workbooks@2026-06-01-preview' = {
  id: '3b0f3eee-3047-526b-aae0-e259182d264d'
  name: 'Microsoft Defender For Office 365'
  content: {
    version: 'Notebook/1.0'
    items: [
      {
        type: 1
        content: {
          json: '## Microsoft Defender for Office 365\n---\n'
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
                durationMs: 604800000
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
              description: 'View release history for this workbook'
              isRequired: true
              value: 'Hide'
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
                json: '### Email Event Analysis Workbook, version 0.2\r\n\r\nauthor: Brian Delaney, MSFT\r\n\r\nRelease Notes:\r\n\r\n1.0 - Oct 18, 2021\r\n- Initial Release\r\n'
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
              linkLabel: 'By Email'
              subTarget: 'Email'
              style: 'link'
            }
            {
              id: '30e93159-8bf5-4006-820f-406ea10bcd17'
              cellValue: 'Nav'
              linkTarget: 'parameter'
              linkLabel: 'By Attachment'
              subTarget: 'Attachments'
              style: 'link'
            }
            {
              id: 'c40f76ed-94be-40ff-b65b-3fda306f2c3d'
              cellValue: 'Nav'
              linkTarget: 'parameter'
              linkLabel: 'By Url'
              subTarget: 'Url'
              style: 'link'
            }
          ]
        }
        name: 'links - 8'
      }
      {
        type: 9
        content: {
          version: 'KqlParameterItem/1.0'
          parameters: [
            {
              id: 'd6592a34-1ae6-4128-9a72-b9aa6295a0c7'
              version: 'KqlParameterItem/1.0'
              name: 'EmailDirection'
              type: 2
              isRequired: true
              multiSelect: true
              quote: '\''
              delimiter: ','
              query: '''
EmailEvents
| summarize Count=count() by EmailDirection
| sort by Count desc
| project EmailDirection, Label=strcat(EmailDirection, ' - ', Count, ' messages')
              '''
              value: [
                'value::all'
              ]
              typeSettings: {
                additionalResourceOptions: [
                  'value::all'
                ]
                showDefault: false
              }
              timeContext: {
                durationMs: 86400000
              }
              timeContextFromParameter: 'TimeRange'
              defaultValue: 'value::all'
              queryType: 'advancedHunting'
            }
            {
              id: 'e63f1a36-a44c-4936-8ad9-30bc7d8587d4'
              version: 'KqlParameterItem/1.0'
              name: 'Sender'
              label: 'Sender Email'
              type: 1
              timeContext: {
                durationMs: 86400000
              }
              value: ''
            }
            {
              id: '175b1a45-d1f0-4e23-b1dd-a19afab7ef7b'
              version: 'KqlParameterItem/1.0'
              name: 'Recipient'
              label: 'Recipient Email'
              type: 1
              value: ''
              timeContext: {
                durationMs: 86400000
              }
            }
            {
              id: '08bf6816-f40b-46d3-b526-25c846728374'
              version: 'KqlParameterItem/1.0'
              name: 'RecipientDomain'
              type: 2
              isRequired: true
              multiSelect: true
              quote: '\''
              delimiter: ','
              query: '''
EmailEvents
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| summarize Messages=count() by RecipientDomain
| sort by Messages desc
| project RecipientDomain, strcat(RecipientDomain, ' - ', Messages, ' messages')
              '''
              value: [
                'value::all'
              ]
              typeSettings: {
                additionalResourceOptions: [
                  'value::all'
                ]
                selectAllValue: '*'
                showDefault: false
              }
              timeContext: {
                durationMs: 0
              }
              timeContextFromParameter: 'TimeRange'
              queryType: 'advancedHunting'
            }
            {
              id: '4046b6e4-7487-48e2-a99f-b74975c738e5'
              version: 'KqlParameterItem/1.0'
              name: 'SenderDomain'
              type: 2
              isRequired: true
              multiSelect: true
              quote: '\''
              delimiter: ','
              query: '''
EmailEvents
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
//| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| summarize Messages=count() by SenderMailFromDomain
| sort by Messages desc
| project SenderMailFromDomain, strcat(SenderMailFromDomain, ' - ', Messages, ' messages')
              '''
              typeSettings: {
                additionalResourceOptions: [
                  'value::all'
                ]
                selectAllValue: '*'
                showDefault: false
              }
              timeContext: {
                durationMs: 0
              }
              timeContextFromParameter: 'TimeRange'
              defaultValue: 'value::all'
              queryType: 'advancedHunting'
            }
            {
              id: '86a41861-0346-4a1a-95f7-8e1b5db915c1'
              version: 'KqlParameterItem/1.0'
              name: 'Subject'
              type: 1
              value: ''
              timeContext: {
                durationMs: 0
              }
              timeContextFromParameter: 'TimeRange'
            }
            {
              id: 'ae9bd4c6-f68a-486b-ba8b-1b8abf27e67d'
              version: 'KqlParameterItem/1.0'
              name: 'MinimumAttachmentCount'
              type: 2
              description: 'Only include messages that have at least this many attachments'
              isRequired: true
              query: 'range x from 0 to 10 step 1'
              value: '0'
              typeSettings: {
                additionalResourceOptions: []
                showDefault: false
              }
              timeContext: {
                durationMs: 86400000
              }
              timeContextFromParameter: 'TimeRange'
              queryType: 'advancedHunting'
            }
            {
              id: 'a7bc4598-cf37-45b5-9049-ac62678f147b'
              version: 'KqlParameterItem/1.0'
              name: 'MinimumURLCount'
              type: 2
              description: 'Only include messages that have at least these many embedded URLs'
              isRequired: true
              query: 'range x from 0 to 20 step 1'
              value: '0'
              typeSettings: {
                additionalResourceOptions: []
                showDefault: false
              }
              timeContext: {
                durationMs: 604800000
              }
              timeContextFromParameter: 'TimeRange'
              queryType: 'advancedHunting'
            }
          ]
          style: 'above'
        }
        name: 'parameters - 1 - Copy'
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
EmailEvents
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize Count=count() by EmailDirection
| sort by Count desc
                '''
                size: 1
                title: 'Email Direction'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'EmailDirection'
                exportParameterName: 'Direction'
                exportDefaultValue: 'All'
                queryType: 'advancedHunting'
                visualization: 'tiles'
                tileSettings: {
                  showBorder: false
                  titleContent: {
                    columnMatch: 'EmailDirection'
                    formatter: 1
                  }
                  leftContent: {
                    columnMatch: 'Count'
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
              customWidth: '45'
              conditionalVisibility: {
                parameterName: 'Nav'
                comparison: 'isNotEqualTo'
                value: 'Attachments'
              }
              name: 'query - 5'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
EmailEvents
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize Count=count() by DeliveryAction
| sort by Count desc
                '''
                size: 1
                title: 'Delivery Action'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'DeliveryAction'
                exportParameterName: 'DeliveryAction'
                exportDefaultValue: 'All'
                queryType: 'advancedHunting'
                visualization: 'tiles'
                tileSettings: {
                  titleContent: {
                    columnMatch: 'DeliveryAction'
                    formatter: 1
                  }
                  leftContent: {
                    columnMatch: 'Count'
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
                  showBorder: false
                }
              }
              customWidth: '25'
              conditionalVisibility: {
                parameterName: 'Nav'
                comparison: 'isNotEqualTo'
                value: 'Attachments'
              }
              name: 'query - 5 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
EmailEvents
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| where "{DeliveryAction}" == "All" or DeliveryAction == "{DeliveryAction}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize Count=count() by bin(Timestamp, {TimeRange:grain}), EmailDirection
                '''
                size: 1
                title: 'Email Timeline'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'EmailAction'
                exportParameterName: 'Action'
                exportDefaultValue: 'All'
                queryType: 'advancedHunting'
                visualization: 'timechart'
                tileSettings: {
                  titleContent: {
                    columnMatch: 'DeliveryAction'
                    formatter: 1
                  }
                  leftContent: {
                    columnMatch: 'Count'
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
                  showBorder: false
                }
              }
              customWidth: '30'
              conditionalVisibility: {
                parameterName: 'Nav'
                comparison: 'isNotEqualTo'
                value: 'Attachments'
              }
              name: 'query - 5 - Copy - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
EmailEvents
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| where "{DeliveryAction}" == "All" or DeliveryAction == "{DeliveryAction}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize DistinctMessages=dcount(InternetMessageId), DistinctRecipients=dcount(RecipientEmailAddress), DistinctRecipientDomains=dcount(RecipientDomain), NetworkMessageIds=tostring(make_set(NetworkMessageId)) by SenderMailFromAddress
| sort by DistinctMessages desc
                '''
                size: 0
                title: 'Top Senders'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportedParameters: [
                  {
                    fieldName: 'SenderMailFromAddress'
                    parameterName: 'Sender2'
                    defaultValue: 'All'
                  }
                  {
                    fieldName: 'NetworkMessageIds'
                    parameterName: 'NetworkMessageIdsSender'
                    parameterType: 1
                    defaultValue: '[]'
                  }
                ]
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'SenderMailFromAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '29ch'
                      }
                    }
                    {
                      columnMatch: 'DistinctMessages'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '20ch'
                      }
                    }
                    {
                      columnMatch: 'DistinctRecipients'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '21ch'
                      }
                    }
                    {
                      columnMatch: 'DistinctRecipientDomains'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '27ch'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageIds'
                      formatter: 5
                    }
                  ]
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
EmailEvents
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where "{Sender2}" == "All" or SenderMailFromAddress =~ "{Sender2}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| where "{DeliveryAction}" == "All" or DeliveryAction == "{DeliveryAction}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize DistinctMessages=dcount(InternetMessageId), DistinctSenders=dcount(SenderMailFromAddress), NetworkMessageIds=tostring(make_set(NetworkMessageId)) by RecipientEmailAddress
| sort by DistinctMessages
                '''
                size: 0
                title: 'Top Recipients'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageIds'
                exportParameterName: 'NetworkMessageIdsRecipient'
                exportDefaultValue: '[]'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'RecipientEmailAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '28ch'
                      }
                    }
                    {
                      columnMatch: 'DistinctMessages'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '143px'
                      }
                    }
                    {
                      columnMatch: 'DistinctSenders'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '140px'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageIds'
                      formatter: 5
                    }
                  ]
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
EmailEvents
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where "{Sender2}" == "All" or SenderMailFromAddress =~ "{Sender2}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| where "{DeliveryAction}" == "All" or DeliveryAction == "{DeliveryAction}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize DistinctMessages=dcount(InternetMessageId), DistinctSenders=dcount(SenderMailFromAddress), NetworkMessageIds=tostring(make_set(NetworkMessageId)) by RecipientDomain
| sort by DistinctMessages desc
                '''
                size: 0
                title: 'Top Recipient Domains'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageIds'
                exportParameterName: 'NetworkMessageIdsDomain'
                exportDefaultValue: '[]'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'RecipientDomain'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '25.8571ch'
                      }
                    }
                    {
                      columnMatch: 'DistinctMessages'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '143px'
                      }
                    }
                    {
                      columnMatch: 'DistinctSenders'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '140px'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageIds'
                      formatter: 5
                    }
                  ]
                }
              }
              customWidth: '30'
              name: 'query - 0 - Copy - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let ids = array_concat(dynamic({NetworkMessageIdsSender}),dynamic({NetworkMessageIdsRecipient}),dynamic({NetworkMessageIdsDomain}));
EmailEvents
| where NetworkMessageId in (ids) or array_length(ids) == 0
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where "{Sender2}" == "All" or SenderMailFromAddress =~ "{Sender2}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| where "{Direction}" == "All" or EmailDirection == "{Direction}"
| where "{DeliveryAction}" == "All" or DeliveryAction == "{DeliveryAction}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| project Timestamp, SenderMailFromAddress, RecipientEmailAddress, Subject, EmailDirection, EmailLanguage, DeliveryAction, ConfidenceLevel, AttachmentCount, UrlCount, NetworkMessageId
                '''
                size: 0
                showAnalytics: true
                title: 'Message Details'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageId'
                exportParameterName: 'NetworkMessageId'
                exportDefaultValue: 'None'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'SenderMailFromAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '30ch'
                      }
                    }
                    {
                      columnMatch: 'RecipientEmailAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '30ch'
                      }
                    }
                    {
                      columnMatch: 'Subject'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '35ch'
                      }
                    }
                    {
                      columnMatch: 'EmailDirection'
                      formatter: 18
                      formatOptions: {
                        thresholdsOptions: 'icons'
                        thresholdsGrid: [
                          {
                            operator: '=='
                            thresholdValue: 'Outbound'
                            representation: 'right'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Inbound'
                            representation: 'left'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Intra-org'
                            representation: 'Pending'
                            text: '{0}{1}'
                          }
                          {
                            operator: 'Default'
                            thresholdValue: null
                            representation: 'unknown'
                            text: '{0}{1}'
                          }
                        ]
                      }
                    }
                    {
                      columnMatch: 'DeliveryAction'
                      formatter: 18
                      formatOptions: {
                        thresholdsOptions: 'icons'
                        thresholdsGrid: [
                          {
                            operator: '=='
                            thresholdValue: 'Delivered'
                            representation: 'success'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Blocked'
                            representation: 'failed'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Junked'
                            representation: 'Disable'
                            text: '{0}{1}'
                          }
                          {
                            operator: 'Default'
                            thresholdValue: null
                            representation: 'unknown'
                            text: '{0}{1}'
                          }
                        ]
                      }
                    }
                    {
                      columnMatch: 'ConfidenceLevel'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '25ch'
                      }
                    }
                    {
                      columnMatch: 'AttachmentCount'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'UrlCount'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageId'
                      formatter: 5
                    }
                  ]
                }
              }
              name: 'query - 6'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
EmailAttachmentInfo
| where NetworkMessageId == "{NetworkMessageId}"
| project FileName, FileType, SHA256, ThreatTypes, ThreatNames, DetectionMethods
                '''
                size: 0
                title: 'Attached Files'
                noDataMessage: 'Either no message was selected or no attachments were present'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
              }
              customWidth: '50'
              name: 'query - 7'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
EmailUrlInfo
| where NetworkMessageId == "{NetworkMessageId}"
| project Url, UrlDomain
                '''
                size: 0
                title: 'Embedded URLs'
                noDataMessage: 'Either no message was selected or no URLs were present'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                queryType: 'advancedHunting'
              }
              customWidth: '50'
              name: 'query - 7 - Copy'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'Nav'
          comparison: 'isEqualTo'
          value: 'Email'
        }
        name: 'EmailGroup'
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
EmailEvents
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize TotalAttachments=sum(AttachmentCount), DistinctRecipients=dcount(RecipientEmailAddress), DistinctRecipientDomains=dcount(RecipientDomain), NetworkMessageIds=tostring(make_set(NetworkMessageId)) by SenderMailFromAddress
| where TotalAttachments > 0
| sort by TotalAttachments desc
                '''
                size: 0
                title: 'Top Attachment Senders'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportedParameters: [
                  {
                    fieldName: 'SenderMailFromAddress'
                    parameterName: 'Sender2'
                    defaultValue: 'All'
                  }
                  {
                    fieldName: 'NetworkMessageIds'
                    parameterName: 'NetworkMessageIdsSender'
                    parameterType: 1
                    defaultValue: '[]'
                  }
                ]
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'SenderMailFromAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '27ch'
                      }
                    }
                    {
                      columnMatch: 'TotalAttachments'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '150px'
                      }
                    }
                    {
                      columnMatch: 'DistinctRecipients'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '21ch'
                      }
                    }
                    {
                      columnMatch: 'DistinctRecipientDomains'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '27ch'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageIds'
                      formatter: 5
                    }
                  ]
                }
              }
              customWidth: '40'
              name: 'query - 0 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
EmailEvents
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where "{Sender2}" == "All" or SenderMailFromAddress =~ "{Sender2}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize TotalAttachments=sum(AttachmentCount), DistinctSenders=dcount(SenderMailFromAddress), NetworkMessageIds=tostring(make_set(NetworkMessageId)) by RecipientEmailAddress
| where TotalAttachments > 0
| sort by TotalAttachments desc
                '''
                size: 0
                title: 'Top Attachment Recipients'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageIds'
                exportParameterName: 'NetworkMessageIdsRecipient'
                exportDefaultValue: '[]'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'RecipientEmailAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '28ch'
                      }
                    }
                    {
                      columnMatch: 'TotalAttachments'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '20ch'
                      }
                    }
                    {
                      columnMatch: 'DistinctSenders'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '140px'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageIds'
                      formatter: 5
                    }
                  ]
                }
              }
              customWidth: '30'
              name: 'query - 0 - Copy - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
EmailEvents
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where "{Sender2}" == "All" or SenderMailFromAddress =~ "{Sender2}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize TotalAttachments=sum(AttachmentCount), DistinctSenders=dcount(SenderMailFromAddress), NetworkMessageIds=tostring(make_set(NetworkMessageId)) by RecipientDomain
| where TotalAttachments > 0
| sort by TotalAttachments desc
                '''
                size: 0
                title: 'Top Attachment Recipient Domains'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageIds'
                exportParameterName: 'NetworkMessageIdsDomain'
                exportDefaultValue: '[]'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'RecipientDomain'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '25.8571ch'
                      }
                    }
                    {
                      columnMatch: 'TotalAttachments'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '22ch'
                      }
                    }
                    {
                      columnMatch: 'DistinctSenders'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '140px'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageIds'
                      formatter: 5
                    }
                  ]
                }
              }
              customWidth: '30'
              name: 'query - 0 - Copy - Copy - Copy'
            }
            {
              type: 9
              content: {
                version: 'KqlParameterItem/1.0'
                parameters: [
                  {
                    id: '16f2ef9f-f59b-4a34-87c7-561c4bbfa92e'
                    version: 'KqlParameterItem/1.0'
                    name: 'AttachmentName'
                    type: 1
                    timeContext: {
                      durationMs: 86400000
                    }
                    timeContextFromParameter: 'TimeRange'
                    value: ''
                  }
                  {
                    id: 'a64d4d00-7f7b-4fc0-991e-1b14e2f7ed1b'
                    version: 'KqlParameterItem/1.0'
                    name: 'AttachmentType'
                    type: 2
                    isRequired: true
                    multiSelect: true
                    quote: '\''
                    delimiter: ','
                    query: '''
EmailAttachmentInfo
| summarize AttachmentCount=count() by FileType
| sort by AttachmentCount desc
| project FileType, strcat(FileType, ' - ', AttachmentCount, ' attachments')
                    '''
                    value: [
                      'value::all'
                    ]
                    typeSettings: {
                      additionalResourceOptions: [
                        'value::all'
                      ]
                      selectAllValue: '*'
                      showDefault: false
                    }
                    timeContext: {
                      durationMs: 0
                    }
                    timeContextFromParameter: 'TimeRange'
                    defaultValue: 'value::all'
                    queryType: 'advancedHunting'
                  }
                ]
                style: 'above'
              }
              name: 'parameters - 1'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let ids = array_concat(dynamic({NetworkMessageIdsSender}),dynamic({NetworkMessageIdsRecipient}),dynamic({NetworkMessageIdsDomain}));
EmailAttachmentInfo
| where NetworkMessageId in (ids) or array_length(ids) == 0
| where FileName contains "{AttachmentName}"
| where "*" in ({AttachmentType}) or FileType in ({AttachmentType})
| summarize UniqueEmailsWithThisAttachment=dcount(NetworkMessageId), NetworkMessageIdWithFile=tostring(make_set(NetworkMessageId)) by FileName, FileType, SHA256
                '''
                size: 0
                showAnalytics: true
                timeContext: {
                  durationMs: 0
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageIdWithFile'
                exportParameterName: 'NetworkMessageIdWithFile'
                exportDefaultValue: '[]'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'NetworkMessageIdWithFile'
                      formatter: 5
                    }
                  ]
                  sortBy: [
                    {
                      itemKey: 'FileName'
                      sortOrder: 1
                    }
                  ]
                }
                sortBy: [
                  {
                    itemKey: 'FileName'
                    sortOrder: 1
                  }
                ]
              }
              name: 'query - 0'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let ids = dynamic({NetworkMessageIdWithFile});
EmailAttachmentInfo
| where NetworkMessageId in (ids)
| distinct NetworkMessageId
| join kind=leftouter (EmailEvents) on NetworkMessageId
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| project Timestamp, SenderMailFromAddress, RecipientEmailAddress, Subject, EmailDirection, EmailLanguage, DeliveryAction, ConfidenceLevel, AttachmentCount, UrlCount, NetworkMessageId
                '''
                size: 0
                showAnalytics: true
                title: 'Message Details'
                noDataMessage: 'No file attachments were selected'
                timeContext: {
                  durationMs: 0
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageId'
                exportParameterName: 'NetworkMessageId'
                exportDefaultValue: 'None'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'SenderMailFromAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '30ch'
                      }
                    }
                    {
                      columnMatch: 'RecipientEmailAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '30ch'
                      }
                    }
                    {
                      columnMatch: 'Subject'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '35ch'
                      }
                    }
                    {
                      columnMatch: 'EmailDirection'
                      formatter: 18
                      formatOptions: {
                        thresholdsOptions: 'icons'
                        thresholdsGrid: [
                          {
                            operator: '=='
                            thresholdValue: 'Outbound'
                            representation: 'right'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Inbound'
                            representation: 'left'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Intra-org'
                            representation: 'Pending'
                            text: '{0}{1}'
                          }
                          {
                            operator: 'Default'
                            thresholdValue: null
                            representation: 'unknown'
                            text: '{0}{1}'
                          }
                        ]
                      }
                    }
                    {
                      columnMatch: 'DeliveryAction'
                      formatter: 18
                      formatOptions: {
                        thresholdsOptions: 'icons'
                        thresholdsGrid: [
                          {
                            operator: '=='
                            thresholdValue: 'Delivered'
                            representation: 'success'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Blocked'
                            representation: 'failed'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Junked'
                            representation: 'Disable'
                            text: '{0}{1}'
                          }
                          {
                            operator: 'Default'
                            thresholdValue: null
                            representation: 'unknown'
                            text: '{0}{1}'
                          }
                        ]
                      }
                    }
                    {
                      columnMatch: 'ConfidenceLevel'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '25ch'
                      }
                    }
                    {
                      columnMatch: 'AttachmentCount'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'UrlCount'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageId'
                      formatter: 5
                    }
                  ]
                }
              }
              name: 'query - 6 - Copy'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'Nav'
          comparison: 'isEqualTo'
          value: 'Attachments'
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
EmailEvents
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize TotalUrls=sum(UrlCount), DistinctRecipients=dcount(RecipientEmailAddress), DistinctRecipientDomains=dcount(RecipientDomain), NetworkMessageIds=tostring(make_set(NetworkMessageId)) by SenderMailFromAddress
| where TotalUrls > 0
| sort by TotalUrls desc
                '''
                size: 0
                title: 'Top Url Senders'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportedParameters: [
                  {
                    fieldName: 'SenderMailFromAddress'
                    parameterName: 'Sender2'
                    defaultValue: 'All'
                  }
                  {
                    fieldName: 'NetworkMessageIds'
                    parameterName: 'NetworkMessageIdsSender'
                    parameterType: 1
                    defaultValue: '[]'
                  }
                ]
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'SenderMailFromAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '27ch'
                      }
                    }
                    {
                      columnMatch: 'TotalUrls'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'DistinctRecipients'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '21ch'
                      }
                    }
                    {
                      columnMatch: 'DistinctRecipientDomains'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '27ch'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageIds'
                      formatter: 5
                    }
                  ]
                }
              }
              customWidth: '40'
              name: 'query - 0 - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
EmailEvents
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where "{Sender2}" == "All" or SenderMailFromAddress =~ "{Sender2}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize TotalUrls=sum(UrlCount), DistinctSenders=dcount(SenderMailFromAddress), NetworkMessageIds=tostring(make_set(NetworkMessageId)) by RecipientEmailAddress
| where TotalUrls > 0
| sort by TotalUrls desc
                '''
                size: 0
                title: 'Top Url Recipients'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageIds'
                exportParameterName: 'NetworkMessageIdsRecipient'
                exportDefaultValue: '[]'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'RecipientEmailAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '28ch'
                      }
                    }
                    {
                      columnMatch: 'TotalUrls'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'DistinctSenders'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '140px'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageIds'
                      formatter: 5
                    }
                  ]
                }
              }
              customWidth: '30'
              name: 'query - 0 - Copy - Copy'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
EmailEvents
| where EmailDirection in ({EmailDirection})
| where AttachmentCount >= {MinimumAttachmentCount} and UrlCount >= {MinimumURLCount}
| where isempty("{Sender}") or SenderMailFromAddress =~ "{Sender}"
| where "{Sender2}" == "All" or SenderMailFromAddress =~ "{Sender2}"
| where isempty("{Recipient}") or RecipientEmailAddress =~ "{Recipient}"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| where "*" in ({RecipientDomain}) or RecipientDomain in ({RecipientDomain})
| where "*" in ({SenderDomain}) or SenderMailFromDomain in ({SenderDomain})
| where isempty("{Subject}") or Subject contains "{Subject}"
| summarize TotalUrls=sum(UrlCount), DistinctSenders=dcount(SenderMailFromAddress), NetworkMessageIds=tostring(make_set(NetworkMessageId)) by RecipientDomain
| where TotalUrls > 0
| sort by TotalUrls desc
                '''
                size: 0
                title: 'Top Url Recipient Domains'
                timeContext: {
                  durationMs: 604800000
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageIds'
                exportParameterName: 'NetworkMessageIdsDomain'
                exportDefaultValue: '[]'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'RecipientDomain'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '25.8571ch'
                      }
                    }
                    {
                      columnMatch: 'TotalUrls'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'DistinctSenders'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                        customColumnWidthSetting: '140px'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageIds'
                      formatter: 5
                    }
                  ]
                }
              }
              customWidth: '30'
              name: 'query - 0 - Copy - Copy - Copy'
            }
            {
              type: 9
              content: {
                version: 'KqlParameterItem/1.0'
                parameters: [
                  {
                    id: '16f2ef9f-f59b-4a34-87c7-561c4bbfa92e'
                    version: 'KqlParameterItem/1.0'
                    name: 'Url'
                    type: 1
                    timeContext: {
                      durationMs: 86400000
                    }
                    timeContextFromParameter: 'TimeRange'
                    value: ''
                  }
                  {
                    id: 'a64d4d00-7f7b-4fc0-991e-1b14e2f7ed1b'
                    version: 'KqlParameterItem/1.0'
                    name: 'UrlDomain'
                    type: 2
                    isRequired: true
                    multiSelect: true
                    quote: '\''
                    delimiter: ','
                    query: '''
EmailUrlInfo
| summarize UrlCount=count() by UrlDomain
| sort by UrlCount desc
| project UrlDomain, strcat(UrlDomain, ' - ', UrlCount, ' URLs')
                    '''
                    value: [
                      'value::all'
                    ]
                    typeSettings: {
                      additionalResourceOptions: [
                        'value::all'
                      ]
                      selectAllValue: '*'
                      showDefault: false
                    }
                    timeContext: {
                      durationMs: 0
                    }
                    timeContextFromParameter: 'TimeRange'
                    defaultValue: 'value::all'
                    queryType: 'advancedHunting'
                  }
                ]
                style: 'above'
              }
              name: 'parameters - 1'
            }
            {
              type: 3
              content: {
                version: 'KqlItem/1.0'
                query: '''
let ids = array_concat(dynamic({NetworkMessageIdsSender}),dynamic({NetworkMessageIdsRecipient}),dynamic({NetworkMessageIdsDomain}));
EmailUrlInfo
| where NetworkMessageId in (ids) or array_length(ids) == 0
| where Url contains "{Url}"
| where "*" in ({UrlDomain}) or UrlDomain in ({UrlDomain})
| summarize UniqueMessagesWithUrl=dcount(NetworkMessageId), NetworkMessageIdWithUrl=tostring(make_set(NetworkMessageId)) by Url, UrlDomain
                '''
                size: 0
                showAnalytics: true
                timeContext: {
                  durationMs: 0
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageIdWithUrl'
                exportParameterName: 'NetworkMessageIdWithUrl'
                exportDefaultValue: '[]'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'NetworkMessageIdWithUrl'
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
let ids = dynamic({NetworkMessageIdWithUrl});
EmailUrlInfo
| where NetworkMessageId in (ids)
| distinct NetworkMessageId
| join kind=leftouter (EmailEvents) on NetworkMessageId
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@", 1)[0])
| project Timestamp, SenderMailFromAddress, RecipientEmailAddress, Subject, EmailDirection, EmailLanguage, DeliveryAction, ConfidenceLevel, AttachmentCount, UrlCount, NetworkMessageId
| sort by Timestamp desc
                '''
                size: 0
                showAnalytics: true
                title: 'Message Details'
                noDataMessage: 'No URLs were selected'
                timeContext: {
                  durationMs: 0
                }
                timeContextFromParameter: 'TimeRange'
                exportFieldName: 'NetworkMessageId'
                exportParameterName: 'NetworkMessageId'
                exportDefaultValue: 'None'
                queryType: 'advancedHunting'
                gridSettings: {
                  formatters: [
                    {
                      columnMatch: 'SenderMailFromAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '30ch'
                      }
                    }
                    {
                      columnMatch: 'RecipientEmailAddress'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '30ch'
                      }
                    }
                    {
                      columnMatch: 'Subject'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '35ch'
                      }
                    }
                    {
                      columnMatch: 'EmailDirection'
                      formatter: 18
                      formatOptions: {
                        thresholdsOptions: 'icons'
                        thresholdsGrid: [
                          {
                            operator: '=='
                            thresholdValue: 'Outbound'
                            representation: 'right'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Inbound'
                            representation: 'left'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Intra-org'
                            representation: 'Pending'
                            text: '{0}{1}'
                          }
                          {
                            operator: 'Default'
                            thresholdValue: null
                            representation: 'unknown'
                            text: '{0}{1}'
                          }
                        ]
                      }
                    }
                    {
                      columnMatch: 'DeliveryAction'
                      formatter: 18
                      formatOptions: {
                        thresholdsOptions: 'icons'
                        thresholdsGrid: [
                          {
                            operator: '=='
                            thresholdValue: 'Delivered'
                            representation: 'success'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Blocked'
                            representation: 'failed'
                            text: '{0}{1}'
                          }
                          {
                            operator: '=='
                            thresholdValue: 'Junked'
                            representation: 'Disable'
                            text: '{0}{1}'
                          }
                          {
                            operator: 'Default'
                            thresholdValue: null
                            representation: 'unknown'
                            text: '{0}{1}'
                          }
                        ]
                      }
                    }
                    {
                      columnMatch: 'ConfidenceLevel'
                      formatter: 0
                      formatOptions: {
                        customColumnWidthSetting: '25ch'
                      }
                    }
                    {
                      columnMatch: 'AttachmentCount'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'UrlCount'
                      formatter: 4
                      formatOptions: {
                        palette: 'blue'
                      }
                    }
                    {
                      columnMatch: 'NetworkMessageId'
                      formatter: 5
                    }
                  ]
                }
              }
              name: 'query - 6 - Copy - Copy'
            }
          ]
        }
        conditionalVisibility: {
          parameterName: 'Nav'
          comparison: 'isEqualTo'
          value: 'Url'
        }
        name: 'UrlGroup'
      }
    ]
  }
}
