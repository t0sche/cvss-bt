# cvss-bt
Enriching the NVD CVSS scores to include Temporal/Threat Metrics

## Overview

The Common Vulnerability Scoring System (CVSS) is an industry standard for assessing the severity of computer system security vulnerabilities. CVSS attempts to establish a measure of how severe a vulnerability is based on its attributes.

The National Vulnerability Database includes CVSS Base scores in its catalog, but base scores are not enough to effectively prioritizie or contextualize vulnerabilities. In this repository I continuously enrich the CVSSv3.x score by using the Exploit Code Maturity (E) Temporal Metric.

### Temporal Metric - Exploit Code Maturity (E)

Source: https://www.first.org/cvss/v3.1/specification-document

| Value | Description | CVE Present In |
|---------------------------|-------------|-------------|
| High (H)                  | Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available. Exploit code works in every situation, or is actively being delivered via an autonomous agent (such as a worm or virus). Network-connected systems are likely to encounter scanning or exploitation attempts. Exploit development has reached the level of reliable, widely available, easy-to-use automated tools. | CISA KEV, EPSS > Threshold, Metasploit |
| Functional (F)            | Functional exploit code is available. The code works in most situations where the vulnerability exists. | Nuclei |
| Proof-of-Concept (P)      | Proof-of-concept exploit code is available. The code might not work in all situations. | ExploitDB |
| Unproven (U)              | No exploit code is available, or an exploit is theoretical. | CVE not present in any threat intelligence source above. |
| Not Defined (X)           | Assigning this value to the metric will not influence the score. It means the user does not have enough information to assign a score. | We drop this value since we have information to assign a score. |



## Features
This repository continuously enriches and publishes CVSSv3.x Temporal Scores based on the following threat intelligence:

- CISA KEV
- EPSS
- Metasploit
- Nuclei
- ExploitDB

### Steps
- Fetches CVSSv3.x scores from NVD every 6 hours
- Fetches EPSS scores every morning
- Calculates the Exploit Code Maturity (E) Metric when new data is found.
- Provides a resulting CVSS-BT score for CVSSv3.x

## To Do
- CVSSv4 Threat Metrics

## Acknowledgements

This product uses the NVD API but is not endorsed or certified by the NVD.