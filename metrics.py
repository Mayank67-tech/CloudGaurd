# metrics.py
from prometheus_client import Gauge, CollectorRegistry, push_to_gateway
import config

registry = CollectorRegistry()

security_score = Gauge('aws_security_posture_score', 'Overall score 0-100', registry=registry)
critical_findings = Gauge('aws_critical_findings_total', 'Critical misconfigs', ['service'], registry=registry)
high_findings = Gauge('aws_high_findings_total', 'High severity findings', ['service'], registry=registry)
medium_findings = Gauge('aws_medium_findings_total', 'Medium severity findings', ['service'], registry=registry)
public_buckets = Gauge('aws_s3_public_buckets_count', 'S3 buckets with public access', registry=registry)
open_ssh_groups = Gauge('aws_open_ssh_security_groups', 'SGs open to 0.0.0.0/0', registry=registry)
mfa_violations = Gauge('aws_iam_users_without_mfa', 'IAM users missing MFA', registry=registry)

def reset_metrics():
    # Reset counts to zero before scan
    for service in set(c['service'] for c in config.CHECKS.values()):
        critical_findings.labels(service=service).set(0)
        high_findings.labels(service=service).set(0)
        medium_findings.labels(service=service).set(0)
    public_buckets.set(0)
    open_ssh_groups.set(0)
    mfa_violations.set(0)

def record_finding(check_id):
    check_info = config.CHECKS.get(check_id)
    if not check_info:
        return
        
    severity = check_info['severity']
    service = check_info['service']
    
    if severity == 'CRITICAL':
        critical_findings.labels(service=service).inc()
    elif severity == 'HIGH':
        high_findings.labels(service=service).inc()
    elif severity == 'MEDIUM':
        medium_findings.labels(service=service).inc()

def push_metrics():
    try:
        push_to_gateway(config.PROMETHEUS_PUSHGATEWAY_URL, job='cloudguard', registry=registry)
        print("Metrics pushed to Prometheus Pushgateway.")
    except Exception as e:
        print(f"Failed to push metrics: {e}")
