# Trust Center Demo — SWT London 2026

**Innovate at Scale: Powering a Secure and Resilient AI Estate**

A live demo showcasing Snowflake Trust Center across four security domains: CIS Benchmarks, PII classification and masking, AI Security, and Threat Intelligence.

## Architecture

```mermaid
flowchart TB
    subgraph trustCenter ["Trust Center — Single Pane of Glass"]
        direction LR
        CIS["CIS Benchmarks\n45 scanners\nCompliance checks"]
        SE["Security Essentials\n8 scanners\nFoundational hygiene"]
        AI["AI Security\n4 scanners\nAgent guardrails"]
        TI["Threat Intelligence\n22 scanners\nReal-time detections"]
    end

    subgraph platform ["Platform Security"]
        AUTH["Authentication\nSSO / MFA"]
        RBAC["Authorization\nRBAC / ABAC"]
        NET["Network Security\nNetwork Policies"]
    end

    subgraph data ["Data Security"]
        CLASS["Classification\nAuto-detect PII"]
        MASK["Masking Policies\nColumn-level protection"]
        ENCRYPT["Encryption\nData integrity"]
    end

    subgraph agent ["Agent Security"]
        IDENTITY["Agent Identity\nScope permissions"]
        GUARD["AI Guardrails\nPrompt injection protection"]
        POSTURE["AI Posture\nSecurity monitoring"]
    end

    trustCenter -->|scans| platform
    trustCenter -->|scans| data
    trustCenter -->|scans| agent

    CIS -.->|"CIS 3.1, 1.4"| NET
    CIS -.->|"CIS 4.10"| MASK
    AI -.->|"Guardrail check"| GUARD
    AI -.->|"Sensitive data access"| IDENTITY
    TI -.->|"Login protection"| AUTH
```

## Files

Run in this order:

| # | File | Purpose |
|---|------|---------|
| 1 | [1_demo_setup.sql](1_demo_setup.sql) | **Pre-flight.** Run before the talk to set the account to the correct starting state. |
| 2 | [2_demo_walkthrough.md](2_demo_walkthrough.md) | **Reference guide.** Step-by-step Snowsight UI navigation with talk track. |
| 3 | [3_demo_trust_center.sql](3_demo_trust_center.sql) | **Main demo.** Open in a Snowsight worksheet and step through the 4 acts on stage. |
| 4 | [4_demo_teardown.sql](4_demo_teardown.sql) | **Cleanup.** Run after the talk to reset state so the demo is repeatable. |
| 5 | [5_demo_violations_setup.sql](5_demo_violations_setup.sql) | **Violations.** Creates demo users, agents, disables guardrails to populate all Trust Center tabs. |
| 6 | [6_demo_violations_teardown.sql](6_demo_violations_teardown.sql) | **Violations cleanup.** Drops demo objects, re-enables guardrails, resets state. |

## Demo Flow (~8 minutes)

```mermaid
flowchart LR
    SETUP["1_demo_setup.sql\nPre-flight"] --> ACT1
    subgraph demo ["3_demo_trust_center.sql"]
        ACT1["Act 1\nTrust Center\nDashboard"] --> ACT2["Act 2\nPII Classification\n& Masking"]
        ACT2 --> ACT3["Act 3\nEnable AI\nSecurity"]
        ACT3 --> ACT4["Act 4\nEnable Threat\nIntelligence"]
    end
    ACT4 --> TEARDOWN["4_demo_teardown.sql\nReset"]
```

| Act | Topic | What Happens |
|-----|-------|--------------|
| 1 | Single Pane of Glass | Open Trust Center, show CIS findings (critical network policy gap, admin-privileged tasks) |
| 2 | PII Classification and Data Protection | Auto-classify HR data, apply tags, show masking policies in action |
| 3 | Agent Security | Enable AI Security live, run scanners for prompt injection, agent data access |
| 4 | Threat Detection | Enable Threat Intelligence live, show login protection and auth failure detection |

## Prerequisites

- Snowflake account with ACCOUNTADMIN access
- Trust Center available (CIS Benchmarks and Security Essentials enabled)
- `DEMO_DB.PUBLIC.HR_DATA` table with PII columns
- `RBAC_DEMO_DB.ANALYST_DATA.STOCK_ANALYST_DATA` table with masking policies

## Links

- [Snowflake Trust Center Documentation](https://docs.snowflake.com/en/user-guide/trust-center)
- [CIS Snowflake Benchmark](https://docs.snowflake.com/en/user-guide/trust-center-cis)
- [Data Classification](https://docs.snowflake.com/en/user-guide/governance-classify-concepts)
- [Dynamic Data Masking](https://docs.snowflake.com/en/user-guide/security-column-ddm-intro)
- [Cortex AI Guardrails](https://docs.snowflake.com/en/user-guide/snowflake-cortex/cortex-guard)
