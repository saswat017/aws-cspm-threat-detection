# CloudWatch Logs Insights (log group /cspm/cloudtrail): who reads secrets, from where
fields @timestamp, userIdentity.arn, sourceIPAddress, eventName, requestParameters.name
| filter eventName in ["GetParameter", "GetParameters", "GetSecretValue", "Decrypt"]
| stats count(*) as reads, earliest(@timestamp) as first_seen by sourceIPAddress, userIdentity.arn
| sort first_seen desc
