# CloudGuard — AWS Security Posture Monitor

![CloudGuard Dashboard](C:/Users/BIT/.gemini/antigravity/brain/093cb2c4-bdfa-4120-a5cd-0b6073bb4832/cloudguard_dashboard_mockup_1779059068937.png)

CloudGuard is a lightweight, automated security auditing tool that continuously scans your AWS environment for critical misconfigurations, calculates a security posture score, and visualizes findings in a real-time Grafana dashboard. It is designed to emulate the security checks performed by enterprise tools like AWS Security Hub and Prowler.

## Features
- **Continuous Auditing:** Uses `boto3` to audit S3, EC2, IAM, EBS, and CloudTrail.
- **Real Security Checks:** Detects public S3 buckets, open SSH security groups, missing IAM MFA, unencrypted volumes, and inactive CloudTrail logs.
- **Dynamic Posture Score (0-100):** Weighted scoring system that deducts points based on the severity of discovered misconfigurations.
- **Prometheus & Grafana Integration:** Automatically pushes metrics to a local Prometheus Pushgateway and visualizes the results on a pre-provisioned Grafana dashboard.
- **Automated Alerting:** Hooks into AWS CloudWatch and SNS to proactively alert administrators of Critical findings (e.g., exposed S3 buckets).

## Tech Stack
- **Language:** Python 3.9
- **AWS SDK:** `boto3`
- **Monitoring:** Prometheus, Prometheus Pushgateway, Grafana
- **Infrastructure:** Docker, Docker Compose

## Getting Started

### Prerequisites
- Docker & Docker Compose
- AWS CLI configured with read-only credentials (e.g., `SecurityAudit` policy)

### Running Locally
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/cloudguard.git
   cd cloudguard
   ```
2. Start the Docker stack (Grafana, Prometheus, and the Python Scanner):
   ```bash
   docker-compose up -d --build
   ```
3. Open your browser and navigate to `http://localhost:3000` to view your live security posture! (No login required).

## Architecture

```
[Python Scanner] ──boto3──► [AWS Account]
      │                         │
      │                    Checks: S3, IAM,
      │                    EC2, CloudTrail...
      │
      ▼
[Prometheus Pushgateway]  ◄── pushes metrics every 5 min
      │
      ▼
[Grafana Dashboard]
  - Security posture score (0-100)
  - Misconfiguration count by severity
  - Historical trend (getting better/worse?)
  - Per-service breakdown
  - Alert History
      │
      ▼
[AWS SNS]
  - Critical finding detected → Email Alert
```

## Deployment
See `DEPLOYMENT_GUIDE.md` for instructions on deploying CloudGuard continuously in a production AWS environment via EC2 or ECS Fargate.
