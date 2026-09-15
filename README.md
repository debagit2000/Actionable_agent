# Actionable_agent
AI Agent which can take action 


┌──────────────────────────────────────────────┐
│ 1. Observability and Event Sources           │
│                                              │
│ • Application and system logs                │
│ • CloudWatch metrics and alarms              │
│ • ELK / OpenSearch events                    │
│ • APM traces                                 │
│ • ECS / EC2 / Load Balancer events           │
│ • Deployment and configuration changes       │
│ • Service desk incidents                     │
└───────────────────────┬──────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────┐
│ 2. Secure Data Ingestion                     │
│                                              │
│ • Normalize event formats                    │
│ • Redact credentials and sensitive data      │
│ • Validate source and timestamp              │
│ • Tag account, region, service and environment│
└───────────────────────┬──────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────┐
│ 3. Smart Incident Engine                     │
│                                              │
│ • Event correlation                          │
│ • Alert deduplication                        │
│ • Noise suppression                          │
│ • Severity and business-impact assessment    │
│ • New incident creation                      │
│ • Existing incident correlation              │
└───────────────────────┬──────────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ Actionable event? │ ## Can be AI based ##
              └─────────┬─────────┘
                        │
              ┌─────────┴──────────┐
              │                    │
            No ▼                  Yes ▼
     Record / Suppress     Create Investigation ID
                                   │
                                   ▼
┌──────────────────────────────────────────────┐
│ 4. AI Agent 1: Observation Agent             │
│                                              │
│ • Understand the alert and affected service  │
│ • Identify error signatures                  │ ## RAG based ## 
│ • Determine initial impact and severity      │
│ • Prepare a read-only diagnostic plan        │
│ • Generate diagnostic commands               │
└───────────────────────┬──────────────────────┘
                        │
                        ▼
                        │
                        ▼
┌──────────────────────────────────────────────┐                                          
│ • Execute commands in a restricted runtime   │
│ • Sanitize collected output                  │
│ • Store evidence under the Investigation ID  │
│ • Pass structured observations to Agent 2    │
└───────────────────────┬──────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────┐
│ 5. AI Agent 2: Investigation Agent           │
│                                              │
│ • Analyze Agent 1's observations             │         
│ • Develop and rank possible hypotheses       │
│ • Request additional read-only diagnostics   |
|    in the same log file                      │
└───────────────────────┬──────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────┐
│ 6. AI Agent 3: RCA and Recommendation Agent  │
│                                              │
│ • Determine probable root cause              │
│ • Build an evidence chain                    │
│ • Estimate blast radius                      │
│ • Recommend remediation options              │
│ • Assign RCA confidence score                │
│ • Identify uncertainty and missing evidence  │
└───────────────────────┬──────────────────────┘
                        │
                        ▼
                Confidence Score P
                        │
              ┌─────────┴─────────┐
              │                   │
          P >= 98%             P < 98%
              │                   │
              ▼                   ▼
     Risk and Policy Gate   AI Agent 4:
                            Deep Research Agent
                                  │
                                  ▼
                   ┌──────────────────────────┐
                   │ • Identify evidence gaps │
                   │ • Collect more logs      │
                   │ • Check ECS/EC2 events   │
                   │ • Review metrics/traces  │
                   │ • Review recent changes  │
                   │ • Search incident history│
                   │ • Recalculate hypotheses │
                   └──────────────┬───────────┘
                                  │
                                  ▼
                       Re-run RCA and Confidence
                                  │
                                  ▼
                     Investigation limit reached?
                                  │
                       ┌──────────┴──────────┐
                       │                     │
                     No ▼                  Yes ▼
              Return to Confidence     Escalate to Human
                    Check              Operations Team
                                            │
                                            ▼
                                 Send Investigation Report
                                 with Evidence and Findings
