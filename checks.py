import boto3
from datetime import datetime, timezone, timedelta
import time
import csv

def check_public_s3_buckets():
    """Returns a list of public S3 buckets."""
    s3 = boto3.client('s3')
    public_buckets = []
    try:
        response = s3.list_buckets()
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            try:
                # Check PublicAccessBlock
                pab = s3.get_public_access_block(Bucket=bucket_name)
                conf = pab.get('PublicAccessBlockConfiguration', {})
                if not (conf.get('BlockPublicAcls') and conf.get('IgnorePublicAcls') and 
                        conf.get('BlockPublicPolicy') and conf.get('RestrictPublicBuckets')):
                    public_buckets.append(bucket_name)
            except Exception as e:
                # If PublicAccessBlock is not set, it might be public depending on ACLs/Policies.
                # We'll err on the side of caution and flag it if NoSuchPublicAccessBlockConfiguration
                if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                    public_buckets.append(bucket_name)
    except Exception as e:
        print(f"Error checking S3 buckets: {e}")
    return public_buckets

def check_open_ssh_security_groups(region):
    """Returns a list of SGs with 0.0.0.0/0 on port 22."""
    ec2 = boto3.client('ec2', region_name=region)
    open_sgs = []
    try:
        paginator = ec2.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            for sg in page.get('SecurityGroups', []):
                for permission in sg.get('IpPermissions', []):
                    if permission.get('IpProtocol') == 'tcp' and permission.get('FromPort', 0) <= 22 <= permission.get('ToPort', 65535):
                        for ip_range in permission.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                open_sgs.append(sg['GroupId'])
    except Exception as e:
        print(f"Error checking Security Groups: {e}")
    return open_sgs

def check_iam_no_mfa():
    """Returns a list of IAM users without MFA enabled."""
    iam = boto3.client('iam')
    users_no_mfa = []
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page.get('Users', []):
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
                if not mfa_devices.get('MFADevices'):
                    users_no_mfa.append(user['UserName'])
    except Exception as e:
        print(f"Error checking IAM MFA: {e}")
    return users_no_mfa

def check_unencrypted_ebs(region):
    """Returns a list of unencrypted EBS volumes."""
    ec2 = boto3.client('ec2', region_name=region)
    unencrypted_vols = []
    try:
        paginator = ec2.get_paginator('describe_volumes')
        for page in paginator.paginate():
            for vol in page.get('Volumes', []):
                if not vol.get('Encrypted', False):
                    unencrypted_vols.append(vol['VolumeId'])
    except Exception as e:
        print(f"Error checking EBS volumes: {e}")
    return unencrypted_vols

def check_cloudtrail_disabled(region):
    """Returns True if CloudTrail is disabled or not logging in the region."""
    cloudtrail = boto3.client('cloudtrail', region_name=region)
    try:
        trails = cloudtrail.describe_trails()
        trail_list = trails.get('trailList', [])
        if not trail_list:
            return True
        for trail in trail_list:
            status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
            if status.get('IsLogging', False):
                return False # At least one trail is active
        return True # Found trails, but none are logging
    except Exception as e:
        print(f"Error checking CloudTrail: {e}")
        return True # Default to disabled on error to raise alert

def check_root_account_used():
    """Returns True if root account was used in the last 30 days."""
    iam = boto3.client('iam')
    try:
        while True:
            resp = iam.generate_credential_report()
            if resp['State'] == 'COMPLETE':
                break
            time.sleep(2)
        
        report = iam.get_credential_report()
        content = report['Content'].decode('utf-8')
        reader = csv.DictReader(content.splitlines())
        
        for row in reader:
            if row['user'] == '<root_account>':
                last_used = row.get('password_last_used', 'N/A')
                if last_used not in ['N/A', 'no_information']:
                    last_used_date = datetime.strptime(last_used[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) - last_used_date < timedelta(days=30):
                        return True
        return False
    except Exception as e:
        print(f"Error checking root account usage: {e}")
        return False

def run_all_checks(region):
    results = {}
    print("Running AWS Security Checks...")
    
    results['public_s3_buckets'] = check_public_s3_buckets()
    results['open_ssh_security_groups'] = check_open_ssh_security_groups(region)
    results['iam_no_mfa'] = check_iam_no_mfa()
    results['unencrypted_ebs'] = check_unencrypted_ebs(region)
    results['cloudtrail_disabled'] = check_cloudtrail_disabled(region)
    results['root_account_used'] = check_root_account_used()
    
    return results
