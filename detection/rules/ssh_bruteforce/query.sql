# CloudWatch Logs Insights (log group /cspm/vpc-flow-logs): top SSH sources
parse @message "* * * * * * * * * * * * * *" as version, account, eni, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, status
| filter dstport = "22"
| stats count(*) as attempts by srcaddr, action
| sort attempts desc
| limit 20
