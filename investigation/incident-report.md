# SOC Incident Report

## Incident Information

| Field                   | Details                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| Incident Type           | Suspicious Authentication Activity / Credential-Guessing Attempt |
| Severity                | Medium                                                           |
| Status                  | Investigated                                                     |
| Tool                    | Splunk                                                           |
| Log Source              | `secure-2`                                                       |
| Primary Suspicious IP   | `87.194.216.51`                                                  |
| Failed Attempts from IP | 41                                                               |

---

## 1. Executive Summary

A review of authentication logs in Splunk identified a high volume of failed password authentication attempts.

The investigation identified repeated attempts against commonly targeted accounts, including `root`, `administrator`, `admin`, and `operator`.

The primary suspicious source investigated was:

**87.194.216.51**

This IP generated **41 failed authentication attempts** in the analyzed data.

The activity is consistent with an attempted credential-guessing or brute-force attack.

Successful authentication events were also present in the dataset; however, the successful authentication activity involved a different source IP and username.

No successful authentication was identified from `87.194.216.51`.

Therefore, there is currently **no confirmed evidence that the investigated suspicious source successfully compromised an account.**

---

## 2. Detection

The investigation began after identifying a large number of failed password events in the security authentication logs.

### SPL Query

```spl
source="tutorialdata.zip:*" sourcetype="secure-2"
| search "Failed password"
```

### Result

The query returned approximately:

**33,253 failed password events**

The volume of failed authentication activity warranted further investigation.

---

## 3. Source IP Investigation

The source IP and username were extracted from the authentication events using the following SPL query:

```spl
source="tutorialdata.zip:*" sourcetype="secure-2"
| search "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count by src_ip user
| sort - count
```

The investigation identified:

**Primary suspicious IP:** `87.194.216.51`

**Failed authentication attempts:** `41`

The repeated authentication attempts from the same source IP indicated potentially automated authentication activity.

---

## 4. Targeted Accounts

The investigation identified several commonly targeted usernames.

| Username      | Failed Attempts |
| ------------- | --------------: |
| root          |           1,493 |
| administrator |           1,020 |
| admin         |             938 |
| operator      |             923 |
| mail          |             753 |

The targeting of multiple common administrative or system accounts is consistent with credential-guessing activity.

---

## 5. Successful Authentication Investigation

To determine whether the suspicious activity resulted in successful access, successful authentication events were searched.

### SPL Query

```spl
source="tutorialdata.zip:*" sourcetype="secure-2"
| search "Accepted"
```

Successful authentication events were identified in the dataset.

However, the successful authentication involved a **different source IP and username** from the suspicious activity investigated in this report.

There was **no successful authentication from `87.194.216.51`**.

### Conclusion

The investigation does not establish a successful compromise associated with the suspicious source IP.

---

## 6. Impact Assessment

### Observed

* High volume of failed authentication attempts
* Repeated targeting of common usernames
* 41 failed attempts from the primary suspicious IP
* Potential automated credential-guessing behavior

### Not Observed

* No successful authentication from the investigated suspicious IP
* No confirmed account compromise
* No confirmed unauthorized access attributable to the investigated source

---

## 7. Severity Assessment

**Severity: Medium**

The incident was classified as Medium because:

* Multiple authentication attempts were observed.
* Common administrative accounts were targeted.
* The activity showed characteristics of automated credential guessing.
* However, there was no confirmed successful authentication from the investigated source.

If successful authentication had been observed from the suspicious IP, the severity would warrant escalation and additional investigation.

---

## 8. Recommended Response

### Immediate Actions

1. Investigate the reputation and history of the suspicious IP.
2. Block or restrict the source IP where appropriate.
3. Review authentication logs for additional activity from the same source.
4. Check whether any targeted accounts experienced suspicious activity.

### Preventive Controls

* Enable multi-factor authentication.
* Implement authentication rate limiting.
* Configure appropriate account lockout controls.
* Disable unnecessary accounts.
* Restrict privileged accounts.
* Use strong password policies.
* Monitor privileged account authentication.

### Detection Improvements

Create SIEM detections for:

* Excessive failed authentication attempts.
* Multiple usernames targeted by one source IP.
* Password spraying patterns.
* Successful authentication following repeated failures.
* Successful authentication from previously suspicious IP addresses.

---

## 9. MITRE ATT&CK Mapping

The observed behavior can be associated with:

**T1110 — Brute Force**

Potential sub-techniques may include:

* Password Guessing
* Password Spraying
* Credential Stuffing

The available log data does not provide enough evidence to definitively determine which specific brute-force sub-technique was used.

---

## 10. Analyst Conclusion

The investigation identified suspicious authentication activity consistent with an attempted credential-guessing or brute-force attack.

The primary suspicious source, `87.194.216.51`, generated 41 failed authentication attempts and activity across commonly targeted usernames.

Although successful authentication events existed elsewhere in the dataset, no successful authentication was observed from the investigated suspicious IP.

### Final Assessment

**Attempted credential attack; no confirmed successful compromise from the investigated source.**
