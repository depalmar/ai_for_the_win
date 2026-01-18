# Lab 48: Cloud Incident Response Automation Walkthrough

Step-by-step guide to building automated IR workflows for cloud environments.

## Overview

This walkthrough guides you through:
1. Designing automated cloud IR workflows
2. Implementing containment actions using serverless
3. Building evidence collection automation
4. Creating detection-to-response pipelines

**Difficulty:** Advanced
**Time:** 120-150 minutes
**Prerequisites:** Lab 25, Lab 44, Labs 46-47

---

## Why Automate Cloud IR?

| Benefit | Description |
|---------|-------------|
| Speed | Sub-minute response to threats |
| Consistency | Same response every time |
| Scale | Handle hundreds of incidents |
| Documentation | Automatic audit trail |
| 24/7 Coverage | No waiting for analysts |

---

## Exercise 1: EC2 Instance Isolation

### Isolate Compromised Instance

```python
import boto3
import json
from datetime import datetime
from typing import Dict

def isolate_ec2_instance(instance_id: str, isolation_sg_id: str, reason: str) -> Dict:
    """Isolate an EC2 instance by replacing security groups."""

    ec2 = boto3.client('ec2')

    # Get current instance details
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]

    # Store original security groups for rollback
    original_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]

    # Tag instance with isolation metadata
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {'Key': 'IR_Isolated', 'Value': 'true'},
            {'Key': 'IR_IsolationTime', 'Value': datetime.utcnow().isoformat()},
            {'Key': 'IR_OriginalSGs', 'Value': json.dumps(original_sgs)},
            {'Key': 'IR_IsolationReason', 'Value': reason}
        ]
    )

    # Replace security groups with isolation SG
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[isolation_sg_id]
    )

    return {
        'status': 'isolated',
        'instance_id': instance_id,
        'original_security_groups': original_sgs,
        'isolation_sg': isolation_sg_id,
        'timestamp': datetime.utcnow().isoformat()
    }

def create_isolation_security_group(vpc_id: str) -> str:
    """Create a security group that blocks all traffic."""

    ec2 = boto3.client('ec2')

    sg = ec2.create_security_group(
        GroupName=f'IR-Isolation-{vpc_id}',
        Description='Incident Response isolation - blocks all traffic',
        VpcId=vpc_id
    )

    # Remove default outbound rule
    ec2.revoke_security_group_egress(
        GroupId=sg['GroupId'],
        IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
    )

    # Add rule to allow only forensics team access
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '10.0.100.0/24'}]  # Forensics subnet
        }]
    )

    return sg['GroupId']
```

---

## Exercise 2: IAM Credential Revocation

### Revoke User Credentials

```python
def revoke_iam_credentials(user_name: str, access_key_id: str = None) -> Dict:
    """Revoke IAM user credentials."""

    iam = boto3.client('iam')
    actions_taken = []

    try:
        # Disable all access keys if none specified
        if access_key_id:
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )
            actions_taken.append(f'Disabled access key {access_key_id}')
        else:
            keys = iam.list_access_keys(UserName=user_name)
            for key in keys['AccessKeyMetadata']:
                iam.update_access_key(
                    UserName=user_name,
                    AccessKeyId=key['AccessKeyId'],
                    Status='Inactive'
                )
                actions_taken.append(f"Disabled access key {key['AccessKeyId']}")

        # Delete login profile (console access)
        try:
            iam.delete_login_profile(UserName=user_name)
            actions_taken.append('Removed console access')
        except iam.exceptions.NoSuchEntityException:
            pass

        # Attach deny-all policy
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
        }

        iam.put_user_policy(
            UserName=user_name,
            PolicyName='IR_DenyAll',
            PolicyDocument=json.dumps(deny_policy)
        )
        actions_taken.append('Attached deny-all policy')

    except Exception as e:
        return {'status': 'error', 'error': str(e), 'actions_taken': actions_taken}

    return {
        'status': 'revoked',
        'user': user_name,
        'actions_taken': actions_taken,
        'timestamp': datetime.utcnow().isoformat()
    }

def invalidate_role_sessions(role_name: str) -> Dict:
    """Invalidate all active sessions for an IAM role."""

    iam = boto3.client('iam')

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName='IR_InvalidateSessions',
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": datetime.utcnow().isoformat()
                    }
                }
            }]
        })
    )

    return {'status': 'sessions_invalidated', 'role': role_name}
```

---

## Exercise 3: Evidence Collection Automation

### Forensic Snapshots

```python
def create_forensic_snapshot(instance_id: str, case_id: str) -> Dict:
    """Create forensic snapshots of all volumes attached to an instance."""

    ec2 = boto3.client('ec2')

    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]

    snapshots = []

    for block_device in instance['BlockDeviceMappings']:
        volume_id = block_device['Ebs']['VolumeId']
        device_name = block_device['DeviceName']

        snapshot = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f'IR Forensic - Case {case_id} - {instance_id} - {device_name}',
            TagSpecifications=[{
                'ResourceType': 'snapshot',
                'Tags': [
                    {'Key': 'IR_CaseId', 'Value': case_id},
                    {'Key': 'IR_InstanceId', 'Value': instance_id},
                    {'Key': 'IR_DeviceName', 'Value': device_name},
                    {'Key': 'IR_Type', 'Value': 'forensic_evidence'}
                ]
            }]
        )

        snapshots.append({
            'snapshot_id': snapshot['SnapshotId'],
            'volume_id': volume_id,
            'device_name': device_name
        })

    return {
        'status': 'snapshots_created',
        'instance_id': instance_id,
        'case_id': case_id,
        'snapshots': snapshots
    }
```

### Log Collection

```python
import time

def collect_cloudtrail_evidence(case_id: str, time_range: Dict, s3_bucket: str) -> Dict:
    """Collect relevant CloudTrail logs for investigation."""

    cloudtrail = boto3.client('cloudtrail')
    s3 = boto3.client('s3')

    events = []
    paginator = cloudtrail.get_paginator('lookup_events')

    for page in paginator.paginate(
        StartTime=time_range['start'],
        EndTime=time_range['end'],
        MaxResults=50
    ):
        events.extend(page['Events'])

    # Save to S3 in forensic bucket
    evidence = {
        'case_id': case_id,
        'collection_time': datetime.utcnow().isoformat(),
        'time_range': {
            'start': time_range['start'].isoformat(),
            'end': time_range['end'].isoformat()
        },
        'event_count': len(events),
        'events': events
    }

    s3.put_object(
        Bucket=s3_bucket,
        Key=f'cases/{case_id}/cloudtrail/events.json',
        Body=json.dumps(evidence, default=str),
        ServerSideEncryption='aws:kms'
    )

    return {
        'status': 'collected',
        'case_id': case_id,
        'event_count': len(events),
        's3_path': f's3://{s3_bucket}/cases/{case_id}/cloudtrail/events.json'
    }
```

### Evidence Integrity

```python
import hashlib
import uuid

def hash_evidence_file(s3_bucket: str, s3_key: str) -> Dict:
    """Calculate and store hash of evidence file."""

    s3 = boto3.client('s3')

    response = s3.get_object(Bucket=s3_bucket, Key=s3_key)
    content = response['Body'].read()

    hashes = {
        'md5': hashlib.md5(content).hexdigest(),
        'sha256': hashlib.sha256(content).hexdigest(),
        'sha512': hashlib.sha512(content).hexdigest()
    }

    # Store hash file
    s3.put_object(
        Bucket=s3_bucket,
        Key=f'{s3_key}.hashes.json',
        Body=json.dumps({
            'original_file': s3_key,
            'file_size': len(content),
            'hashes': hashes,
            'hash_time': datetime.utcnow().isoformat()
        }),
        ServerSideEncryption='aws:kms'
    )

    return hashes

def create_chain_of_custody(case_id: str, evidence_items: list, s3_bucket: str) -> Dict:
    """Create chain of custody record for evidence."""

    s3 = boto3.client('s3')
    sts = boto3.client('sts')

    identity = sts.get_caller_identity()

    custody_record = {
        'case_id': case_id,
        'created_at': datetime.utcnow().isoformat(),
        'created_by': identity['Arn'],
        'evidence_items': [],
        'custody_chain': [{
            'action': 'created',
            'timestamp': datetime.utcnow().isoformat(),
            'actor': identity['Arn']
        }]
    }

    for item in evidence_items:
        hashes = hash_evidence_file(s3_bucket, item['s3_key'])
        custody_record['evidence_items'].append({
            'item_id': str(uuid.uuid4()),
            'description': item['description'],
            's3_path': f"s3://{s3_bucket}/{item['s3_key']}",
            'hashes': hashes
        })

    s3.put_object(
        Bucket=s3_bucket,
        Key=f'cases/{case_id}/chain_of_custody.json',
        Body=json.dumps(custody_record),
        ServerSideEncryption='aws:kms'
    )

    return custody_record
```

---

## Exercise 4: Step Functions Workflow

### Orchestration Definition

```json
{
  "Comment": "Cloud IR Automation Workflow",
  "StartAt": "TriageAlert",
  "States": {
    "TriageAlert": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:ir-triage",
      "Next": "SeverityCheck"
    },
    "SeverityCheck": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.severity",
          "StringEquals": "CRITICAL",
          "Next": "CriticalResponse"
        },
        {
          "Variable": "$.severity",
          "StringEquals": "HIGH",
          "Next": "HighResponse"
        }
      ],
      "Default": "StandardResponse"
    },
    "CriticalResponse": {
      "Type": "Parallel",
      "Branches": [
        {
          "StartAt": "IsolateInstance",
          "States": {
            "IsolateInstance": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:region:account:function:ir-isolate",
              "End": true
            }
          }
        },
        {
          "StartAt": "RevokeCredentials",
          "States": {
            "RevokeCredentials": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:region:account:function:ir-revoke-creds",
              "End": true
            }
          }
        },
        {
          "StartAt": "CreateSnapshots",
          "States": {
            "CreateSnapshots": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:region:account:function:ir-snapshot",
              "End": true
            }
          }
        }
      ],
      "Next": "CollectEvidence"
    },
    "HighResponse": {
      "Type": "Parallel",
      "Branches": [
        {
          "StartAt": "RestrictNetworkAccess",
          "States": {
            "RestrictNetworkAccess": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:region:account:function:ir-restrict-network",
              "End": true
            }
          }
        },
        {
          "StartAt": "CreateSnapshots",
          "States": {
            "CreateSnapshots": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:region:account:function:ir-snapshot",
              "End": true
            }
          }
        }
      ],
      "Next": "CollectEvidence"
    },
    "StandardResponse": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:ir-log-incident",
      "Next": "CollectEvidence"
    },
    "CollectEvidence": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:ir-collect-evidence",
      "Next": "CreateTicket"
    },
    "CreateTicket": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:ir-create-ticket",
      "End": true
    }
  }
}
```

---

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        CLOUD IR AUTOMATION - INCIDENT REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Case ID: IR-2026-0117-001
Severity: CRITICAL
Detection Time: 2026-01-17 14:32:15 UTC
Response Time: 2026-01-17 14:32:47 UTC (32 seconds)

━━━━━ CONTAINMENT ACTIONS ━━━━━
✅ Instance Isolated: i-0abc123def456
   Original SGs: [sg-web-tier]
   Isolation SG: sg-ir-isolation-vpc1

✅ Credentials Revoked: compromised-user
   Actions: Disabled 2 access keys, removed console access

✅ Sessions Invalidated: role-app-backend

━━━━━ EVIDENCE COLLECTED ━━━━━
✅ Disk Snapshots Created:
   - snap-0111222333 (vol-root)
   - snap-0444555666 (vol-data)

✅ CloudTrail Logs: 1,247 events collected
   Path: s3://forensics-bucket/cases/IR-2026-0117-001/

✅ Chain of Custody: Created and signed

━━━━━ NOTIFICATIONS ━━━━━
✅ Slack: #security-incidents
✅ PagerDuty: On-call notified
✅ Ticket: JIRA-SEC-4521 created

━━━━━ NEXT STEPS ━━━━━
1. Forensic analysis of disk snapshots
2. CloudTrail log analysis
3. Determine root cause
4. Plan remediation
```

---

## Resources

- [AWS Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/)
- [NIST Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [AWS Step Functions](https://docs.aws.amazon.com/step-functions/)

---

*Cloud IR Automation Complete!*
