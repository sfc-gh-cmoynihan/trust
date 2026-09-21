# Trust Center Demo — Snowsight UI Walkthrough

## SWT London 2026: Innovate at Scale — Powering a Secure and Resilient AI Estate

**Duration:** ~8 minutes
**Prerequisites:** Run `demo_setup.sql` before going on stage.
**SQL Script:** Have `demo_trust_center.sql` open in a Snowsight worksheet alongside.

---

## Before You Begin

- Open two tabs in Snowsight:
  1. **Trust Center** (Monitoring > Trust Center)
  2. **SQL Worksheet** with `demo_trust_center.sql` loaded
- Ensure you are using **ACCOUNTADMIN** role
- Increase font size in Snowsight for readability (Cmd/Ctrl + Plus)

---

## Act 1: The Single Pane of Glass (~2 min)

### Step 1: Trust Center Dashboard

1. **Navigate** to Trust Center: Monitoring > Trust Center
2. **Point out the overview:**
   - Severity badges at the top — Critical, High, Medium, Low counts
   - Scanner packages listed: CIS Benchmarks (enabled), Security Essentials (enabled)
   - AI Security and Threat Intelligence are listed but **not enabled** — say: "We'll come back to these"
3. **Talk track:** "This is Trust Center — Snowflake's single pane of glass for security, compliance, and governance. It scans your account against industry benchmarks and surfaces exactly what needs attention."

### Step 2: Drill into CIS 3.1 (Critical)

1. **Click** on the CIS Benchmarks package
2. **Find and click** CIS 3.1 — "Ensure that all users are covered by a network policy"
3. **Show:**
   - Severity: **Critical**
   - At-risk entities: **10** (these are users/accounts not covered)
   - Suggested action: The exact SQL to create a network rule and policy
4. **Talk track:** "10 entities without network policy coverage. Trust Center doesn't just flag this — it gives you the exact SQL to fix it. This is the kind of foundational platform security we talked about."

### Step 3: Show High Findings (Tasks with Admin Roles)

1. **Navigate back** to CIS Benchmarks findings list
2. **Point out** CIS 1.14 and 1.15 — "Tasks owned by / running with ACCOUNTADMIN"
3. **Talk track:** "41 tasks running with ACCOUNTADMIN privileges. In the agentic world, this is exactly the over-privileged access pattern that creates risk."

### Transition to SQL

- **Say:** "But what about protecting the data itself? Let me show you classification."
- **Switch** to the SQL Worksheet tab

---

## Act 2: PII Classification and Data Protection (~2 min)

### Step 4: Show the HR Data

1. **In the SQL worksheet**, run:
   ```sql
   SELECT * FROM DEMO_DB.PUBLIC.HR_DATA LIMIT 5;
   ```
2. **Talk track:** "Here's an HR table — names, emails, ages. Let's ask Snowflake to automatically classify what's in it."

### Step 5: Run Auto-Classification

1. **Run:**
   ```sql
   SELECT EXTRACT_SEMANTIC_CATEGORIES('DEMO_DB.PUBLIC.HR_DATA');
   ```
2. **Click on the result** to expand the JSON — point out:
   - EMAIL_ADDRESS identified as `email`
   - FNAME, LNAME identified as `name`
   - AGE identified as `age` / personal identifier
3. **Talk track:** "Snowflake has automatically identified the semantic categories — email, name, age. No manual tagging needed."

### Step 6: Apply Tags

1. **Run:**
   ```sql
   CALL ASSOCIATE_SEMANTIC_CATEGORY_TAGS(
       'DEMO_DB.PUBLIC.HR_DATA',
       EXTRACT_SEMANTIC_CATEGORIES('DEMO_DB.PUBLIC.HR_DATA')
   );
   ```
2. **Optionally verify** with the TAG_REFERENCES query
3. **Talk track:** "Tags applied. Every column now has a semantic category and privacy classification. This is the foundation for automated data protection."

### Step 7: Show Masking in Action

1. **Run the STOCK_ANALYST_DATA query as ACCOUNTADMIN:**
   ```sql
   SELECT REPORT_ID, ANALYST_NAME, ANALYST_EMAIL, ANALYST_PHONE,
          TICKER, RECOMMENDATION, PRICE_TARGET, CONFIDENTIAL_NOTES
   FROM RBAC_DEMO_DB.ANALYST_DATA.STOCK_ANALYST_DATA
   LIMIT 5;
   ```
2. **Point out:** Full visibility — names, emails, price targets, confidential notes all visible
3. **Talk track:** "As an admin, I see everything. But when a restricted role queries the same table, masking policies automatically redact the sensitive fields. Same table, same query — different results based on who's asking. Whether it's a human or an agent."

### Step 8: Connect to Trust Center

1. **Run the CIS 4.10 finding query** to show Trust Center flags unmasked sensitive data
2. **Talk track:** "And Trust Center ties this together — CIS 4.10 flags tables with classified sensitive data that don't yet have masking policies."

### Transition

- **Say:** "So we've got platform security and data protection. Now let's turn on agent security."

---

## Act 3: Agent Security — Enable Live (~2 min)

### Step 9: Show AI Security is Disabled

1. **Run:**
   ```sql
   SELECT ID, NAME, STATE
   FROM snowflake.trust_center.scanner_packages
   WHERE ID = 'AI_SECURITY';
   ```
2. **Point out:** STATE = FALSE
3. **Talk track:** "AI Security is new — purpose-built controls for the agentic era. Right now it's disabled. Let's change that."

### Step 10: Enable AI Security (The Live Moment)

1. **Run:**
   ```sql
   CALL snowflake.trust_center.set_configuration('ENABLED', 'TRUE', 'AI_SECURITY', false);
   ```
2. **Pause for effect**
3. **Talk track:** "One command. That's all it takes."

### Step 11: Show What AI Security Checks

1. **Run the scanners list query**
2. **Walk through each scanner:**
   - Cortex AI Guardrails — prompt injection protection
   - Sensitive Data Accessed by Agent — data exfiltration risk
   - Cortex Search Service Privileged Roles — least privilege
   - Cortex Code PAT Usage — access control
3. **Talk track:** "Four scanners, each addressing a real-world AI security concern."

### Step 12: Run AI Security Scanners

1. **Run:**
   ```sql
   CALL snowflake.trust_center.execute_scanner('AI_SECURITY');
   ```
2. **Query the findings** — show whatever comes back
3. **Talk track:** "The scanners are running. Any findings will appear in Trust Center alongside your CIS and Security Essentials results — all in one place."

### Transition

- **Say:** "The final piece is threat detection."

---

## Act 4: Threat Detection (~2 min)

### Step 13: Enable Threat Intelligence

1. **Run:**
   ```sql
   CALL snowflake.trust_center.set_configuration('ENABLED', 'TRUE', 'THREAT_INTELLIGENCE', false);
   ```
2. **Talk track:** "Threat Intelligence enabled."

### Step 14: Show Detection Scanners

1. **Run the scanners list query**
2. **Highlight key scanners:**
   - **Login Protection** — detects logins from known malicious IP addresses
   - **Dormant User Login** — flags when inactive accounts suddenly wake up
   - **High Auth Failures** — catches brute force attempts
   - **Sensitive Parameter Protection** — alerts when data movement safeguards are disabled
3. **Talk track:** "These aren't just configuration checks — they're active threat detections. Login from a malicious IP? Flagged. Dormant account suddenly active? Flagged. Someone disabling data movement safeguards? Flagged. This is the shift from violations to detections."

### Step 15: Run and Show Full Picture

1. **Run:**
   ```sql
   CALL snowflake.trust_center.execute_scanner('THREAT_INTELLIGENCE');
   ```
2. **Run the closing summary query** — findings across all four packages
3. **Talk track:** "CIS Benchmarks for compliance. Security Essentials for hygiene. AI Security for agent guardrails. Threat Intelligence for real-time detection. All four packages. Every at-risk entity. One place. Proactive, enterprise-grade security for data and AI — built in, not bolted on."

---

## Closing

- **Switch back to slides** — Slide 7: THANK YOU
- Total time: approximately 7-8 minutes

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Scanner package won't enable | Check you're using ACCOUNTADMIN or a role with `trust_center_admin` |
| `execute_scanner` returns no findings | This is fine — it means no issues were found. Emphasise "clean bill of health" |
| Classification returns unexpected results | The JSON output is still demo-worthy — focus on the fact that it auto-detected categories |
| Masking demo fails | Ensure RBAC_DEMO_DB policies are attached. Run `DESCRIBE TABLE` to verify |
| Trust Center UI not loading | Refresh the page. Ensure you're on a supported browser |
