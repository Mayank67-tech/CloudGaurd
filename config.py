import os

CHECKS = {
    'public_s3_buckets':      {'severity': 'CRITICAL', 'weight': 20, 'service': 's3'},
    'open_ssh_security_groups': {'severity': 'HIGH',   'weight': 15, 'service': 'ec2'},
    'iam_no_mfa':             {'severity': 'HIGH',     'weight': 15, 'service': 'iam'},
    'unencrypted_ebs':        {'severity': 'MEDIUM',   'weight': 10, 'service': 'ec2'},
    'cloudtrail_disabled':    {'severity': 'HIGH',     'weight': 15, 'service': 'cloudtrail'},
    'root_account_used':      {'severity': 'CRITICAL', 'weight': 25, 'service': 'iam'},
}

PROMETHEUS_PUSHGATEWAY_URL = os.getenv('PUSHGATEWAY_URL', 'http://localhost:9091')
SCAN_INTERVAL_SECONDS = int(os.getenv('SCAN_INTERVAL_SECONDS', 300))  # 5 minutes

AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1') # Default region for regional checks
SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN', None)
