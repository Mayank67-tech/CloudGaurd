import time
import config
import checks
import metrics
import boto3

def get_posture_score(failed_checks):
    score = 100
    # A check might fail multiple times (e.g. 2 public buckets). 
    # The requirement says "deduct per failing check". 
    # Usually, it's per check type, but let's deduct the weight if the check type fails at all.
    for check_id in set(failed_checks):
        weight = config.CHECKS.get(check_id, {}).get('weight', 0)
        score -= weight
    return max(0, score)

def trigger_cloudwatch_alarm(failed_checks):
    critical_failed = [c for c in failed_checks if config.CHECKS.get(c, {}).get('severity') == 'CRITICAL']
    if critical_failed:
        print(f"[ALERT] CRITICAL FINDINGS DETECTED: {critical_failed}")
        if config.SNS_TOPIC_ARN:
            try:
                sns = boto3.client('sns', region_name=config.AWS_REGION)
                message = f"CloudGuard Alert: Critical AWS Misconfigurations Detected!\n\nFindings:\n"
                for c in critical_failed:
                    message += f"- {c}\n"
                
                sns.publish(
                    TopicArn=config.SNS_TOPIC_ARN,
                    Subject="CRITICAL AWS Security Alert (CloudGuard)",
                    Message=message
                )
                print(f"SNS notification sent to {config.SNS_TOPIC_ARN}")
            except Exception as e:
                print(f"Failed to publish to SNS: {e}")
        else:
            print("SNS_TOPIC_ARN not configured. Skipping SNS notification.")

def main():
    print("Starting CloudGuard AWS Security Posture Monitor...")
    while True:
        try:
            metrics.reset_metrics()
            
            results = checks.run_all_checks(config.AWS_REGION)
            failed_checks = []
            
            if results.get('public_s3_buckets'):
                failed_checks.append('public_s3_buckets')
                metrics.public_buckets.set(len(results['public_s3_buckets']))
                for _ in results['public_s3_buckets']:
                    metrics.record_finding('public_s3_buckets')
            
            if results.get('open_ssh_security_groups'):
                failed_checks.append('open_ssh_security_groups')
                metrics.open_ssh_groups.set(len(results['open_ssh_security_groups']))
                for _ in results['open_ssh_security_groups']:
                    metrics.record_finding('open_ssh_security_groups')
            
            if results.get('iam_no_mfa'):
                failed_checks.append('iam_no_mfa')
                metrics.mfa_violations.set(len(results['iam_no_mfa']))
                for _ in results['iam_no_mfa']:
                    metrics.record_finding('iam_no_mfa')
            
            if results.get('unencrypted_ebs'):
                failed_checks.append('unencrypted_ebs')
                for _ in results['unencrypted_ebs']:
                    metrics.record_finding('unencrypted_ebs')
            
            if results.get('cloudtrail_disabled'):
                failed_checks.append('cloudtrail_disabled')
                metrics.record_finding('cloudtrail_disabled')
            
            if results.get('root_account_used'):
                failed_checks.append('root_account_used')
                metrics.record_finding('root_account_used')
                
            score = get_posture_score(failed_checks)
            metrics.security_score.set(score)
            
            print(f"Scan complete. Failed checks: {set(failed_checks)}. Posture Score: {score}")
            
            metrics.push_metrics()
            trigger_cloudwatch_alarm(failed_checks)
            
        except Exception as e:
            print(f"An error occurred during scan: {e}")
            
        print(f"Sleeping for {config.SCAN_INTERVAL_SECONDS} seconds...")
        time.sleep(config.SCAN_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
