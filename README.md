# SOC Splunk Login Investigation

## Overview

This project documents a Security Operations Center (SOC) investigation of suspicious authentication activity using Splunk.

The objective was to analyze authentication logs, identify abnormal login behavior, investigate suspicious source IP activity, determine which accounts were being targeted, and assess whether the activity resulted in successful unauthorized access.

This investigation simulates a real-world SOC alert investigation involving potential credential-guessing or brute-force activity.

---

## Investigation Objectives

The investigation focused on:

* Identifying abnormal authentication activity
* Analyzing failed login attempts
* Identifying suspicious source IP addresses
* Determining which usernames were being targeted
* Investigating successful authentication events
* Correlating source IP addresses with usernames
* Determining whether the suspicious activity resulted in successful access
* Assessing the severity of the activity
* Recommending appropriate security controls

---

## Tools & Technologies

* **Splunk** — SIEM and log analysis
* **Splunk Search Processing Language (SPL)** — Log querying and investigation
* **Authentication/Security Logs** — Primary investigation data
* **GitHub** — Security investigation documentation and portfolio

---

## Dataset

The investigation was performed using Splunk's tutorial dataset.

The relevant security authentication logs were identified under the `secure-2` sourcetype.

---

# Investigation Process

## 1. Identifying Failed Authentication Activity

The investigation began by searching for failed password authentication events.

### SPL Query

```spl
source="tutorialdata.zip:*" sourcetype="secure-2"
| search "Failed password"
```

### Finding

The search returned approximately:

**33,253 failed password events**

This indicated a significant volume of unsuccessful authentication attempts within the dataset and warranted further investigation.

---

## 2. Identifying Suspicious Source IP Addresses

The next step was to extract the source IP address and username associated with failed authentication attempts.

### SPL Query

```spl
source="tutorialdata.zip:*" sourcetype="secure-2"
| search "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count by src_ip user
| sort - count
```

This allowed the investigation to identify IP addresses generating repeated authentication failures and the accounts they were targeting.

---

## 3. Identifying Targeted Accounts

The analysis revealed repeated attempts against several common and potentially privileged usernames.

### Most Frequently Targeted Usernames

| Username      | Failed Attempts |
| ------------- | --------------: |
| root          |           1,493 |
| administrator |           1,020 |
| admin         |             938 |
| operator      |             923 |
| mail          |             753 |

The repeated targeting of common administrative accounts is consistent with automated credential-guessing activity.

---

## 4. Investigating the Primary Suspicious IP

One source IP was selected for deeper investigation:

**87.194.216.51**

Further analysis identified:

**41 failed authentication attempts**

from this source IP.

The repeated authentication failures from a single external source, combined with the targeting of multiple usernames, increased the likelihood that the activity represented automated credential-guessing rather than normal user behavior.

---

## 5. Investigating Successful Authentication Events

The investigation also searched for successful authentication activity to determine whether the suspicious activity resulted in unauthorized access.

### SPL Query

```spl
source="tutorialdata.zip:*" sourcetype="secure-2"
| search "Accepted"
```

Successful authentication events were identified in the dataset.

However, the successful authentication activity involved a **different username and source IP** from the suspicious IP `87.194.216.51`.

### Assessment

There was **no confirmed successful authentication from the investigated suspicious IP**.

Therefore, the investigation does not establish that the suspicious failed-login activity resulted in a successful compromise.

---

# Key Findings

| Finding                                      | Result          |
| -------------------------------------------- | --------------- |
| Failed password events                       | 33,253          |
| Primary suspicious IP                        | 87.194.216.51   |
| Failed attempts from suspicious IP           | 41              |
| Frequently targeted account                  | root            |
| Successful authentication from suspicious IP | Not observed    |
| Confirmed compromise                         | Not established |

---

# Security Assessment

### Incident Type

**Suspicious Authentication Activity / Credential-Guessing Attempt**

### Severity

**Medium**

### Investigation Status

**Investigated**

### Assessment

The activity is consistent with a potential automated credential-guessing or brute-force attempt.

The high number of failed authentication events and repeated targeting of common administrative usernames warranted investigation.

However, no successful authentication was observed from the primary suspicious IP address. Therefore, there is currently no evidence from this investigation that the identified source successfully compromised an account.

**Final Assessment: Attempted credential attack; no confirmed successful compromise from the investigated source.**

---

# Recommended Response Actions

If this activity were observed in a production environment, recommended actions would include:

### 1. Investigate the Source IP

Review the suspicious IP address and determine whether it is associated with known malicious activity.

Where appropriate, block or restrict the source at the firewall or other relevant security controls.

### 2. Enable Multi-Factor Authentication

Require MFA, particularly for privileged and administrative accounts.

### 3. Implement Account Lockout or Rate Limiting

Limit repeated authentication attempts to reduce the effectiveness of automated credential-guessing attacks.

### 4. Review Privileged Accounts

Review accounts such as:

* root
* administrator
* admin
* operator

Ensure that unnecessary accounts are disabled and privileged access is appropriately controlled.

### 5. Monitor for Future Successful Authentication

Create or tune SIEM alerts to detect successful authentication from previously suspicious IP addresses.

### 6. Continue Log Monitoring

Monitor authentication logs for:

* Repeated failures
* Password spraying patterns
* Brute-force behavior
* Unusual geographic locations
* Unusual login times
* Successful logins following repeated failures

---

# Example SOC Detection Logic

A potential SIEM detection could alert analysts when:

> A single source IP generates a high number of failed authentication attempts against multiple usernames within a short period.

Additional detection logic could correlate:

**Multiple failed logins → suspicious source → successful login**

Such correlation could help identify potential account compromise.

---

# Skills Demonstrated

This project demonstrates practical experience with:

* SIEM investigation
* Splunk
* SPL queries
* Authentication log analysis
* Failed-login investigation
* Source IP analysis
* Username/account analysis
* Event correlation
* Incident severity assessment
* Security investigation documentation
* SOC analyst investigation methodology
* Security recommendations

---

# Evidence

Screenshots from the investigation will be added to this repository to demonstrate the investigation process and findings.

---

# Conclusion

This investigation demonstrated how a SOC analyst can use Splunk to investigate suspicious authentication activity.

The analysis identified a high volume of failed authentication events, several heavily targeted usernames, and a suspicious source IP responsible for repeated failed login attempts.

Although successful authentication events were present elsewhere in the dataset, no successful authentication was identified from the investigated suspicious IP.

The activity was therefore assessed as a **Medium-severity attempted credential attack with no confirmed successful compromise from the investigated source**.
