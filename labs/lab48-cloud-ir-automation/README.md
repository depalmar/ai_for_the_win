# Lab 48: Cloud Incident Response Automation

## Overview

Build automated incident response workflows for cloud environments using infrastructure-as-code, serverless functions, and orchestration tools.

**Difficulty**: Advanced
**Duration**: 120-150 minutes
**Prerequisites**: Lab 25 (DFIR Fundamentals), Lab 44 (Cloud Security), Labs 46-47, understanding of IaC concepts

## Learning Objectives

By the end of this lab, you will be able to:
1. Design automated cloud IR workflows
2. Implement containment actions using serverless
3. Build evidence collection automation
4. Create detection-to-response pipelines
5. Orchestrate multi-cloud incident response

## Background

### Why Automate Cloud IR?

Cloud environments generate massive alert volumes that humans cannot process manually. Automation enables:

| Benefit | Description |
|---------|-------------|
| Speed | Sub-minute response to detected threats |
| Consistency | Same response every time, no human error |
| Scale | Handle hundreds of incidents simultaneously |
| Documentation | Automatic audit trail of all actions |
| 24/7 Coverage | No waiting for analysts to be available |

### IR Automation Architecture

```
Detection Sources          Orchestration           Response Actions
┌─────────────────┐        ┌───────────────┐       ┌─────────────────┐
│ SIEM/XDR Alerts │───────▶│               │──────▶│ Isolate Instance│
├─────────────────┤        │               │       ├─────────────────┤
│ GuardDuty/Cloud │───────▶│   Orchestration/       │──────▶│ Revoke Creds    │
│ Security        │        │   Step        │       ├─────────────────┤
├─────────────────┤        │   Functions   │──────▶│ Snapshot Disk   │
│ Custom Rules    │───────▶│               │       ├─────────────────┤
├─────────────────┤        │               │──────▶│ Block IP        │
│ Anomaly         │───────▶│               │       ├─────────────────┤
│ Detection       │        └───────────────┘       │ Notify Team     │
└─────────────────┘                                └─────────────────┘
```

## Part 1: Containment Automation

### Exercise 1.1: EC2 Instance Isolation

```python
import boto3
import json
from datetime import datetime

def isolate_ec2_instance(instance_id, isolation_sg_id, reason):
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
            {
                'Key': 'IR_Isolated',
                'Value': 'true'
            },
            {
                'Key': 'IR_IsolationTime',
                'Value': datetime.utcnow().isoformat()
            },
            {
                'Key': 'IR_OriginalSGs',
                'Value': json.dumps(original_sgs)
            },
            {
                'Key': 'IR_IsolationReason',
                'Value': reason
            }
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

def create_isolation_security_group(vpc_id):
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
        IpPermissions=[{
            'IpProtocol': '-1',
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }]
    )

    # Add rule to allow only forensics team access
    forensics_cidr = '10.0.100.0/24'  # Forensics workstation subnet

    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': forensics_cidr}]
        }]
    )

    return sg['GroupId']
```

### Exercise 1.2: IAM Credential Revocation

```python
def revoke_iam_credentials(user_name, access_key_id=None):
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
            # Disable all access keys
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

        # Deactivate MFA devices
        mfa_devices = iam.list_mfa_devices(UserName=user_name)
        for device in mfa_devices['MFADevices']:
            iam.deactivate_mfa_device(
                UserName=user_name,
                SerialNumber=device['SerialNumber']
            )
            actions_taken.append(f"Deactivated MFA {device['SerialNumber']}")

        # Attach deny-all policy
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }]
        }

        iam.put_user_policy(
            UserName=user_name,
            PolicyName='IR_DenyAll',
            PolicyDocument=json.dumps(deny_policy)
        )
        actions_taken.append('Attached deny-all policy')

    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'actions_taken': actions_taken
        }

    return {
        'status': 'revoked',
        'user': user_name,
        'actions_taken': actions_taken,
        'timestamp': datetime.utcnow().isoformat()
    }

def invalidate_role_sessions(role_name):
    """Invalidate all active sessions for an IAM role."""

    iam = boto3.client('iam')

    # Get the role
    role = iam.get_role(RoleName=role_name)

    # Update role's assume role policy with a condition that
    # requires session to be issued after current time
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

    return {
        'status': 'sessions_invalidated',
        'role': role_name,
        'timestamp': datetime.utcnow().isoformat()
    }
```

### Exercise 1.3: Network Containment

```python
def block_ip_address(ip_address, reason):
    """Block an IP address using WAF and Network ACL."""

    actions = []

    # Add to WAF IP set
    wafv2 = boto3.client('wafv2')

    try:
        # Get current IP set
        ip_set = wafv2.get_ip_set(
            Name='IR-BlockedIPs',
            Scope='REGIONAL',
            Id='your-ip-set-id'
        )

        current_addresses = ip_set['IPSet']['Addresses']

        # Add new IP (CIDR format)
        ip_cidr = f'{ip_address}/32'
        if ip_cidr not in current_addresses:
            current_addresses.append(ip_cidr)

            wafv2.update_ip_set(
                Name='IR-BlockedIPs',
                Scope='REGIONAL',
                Id='your-ip-set-id',
                Addresses=current_addresses,
                LockToken=ip_set['LockToken']
            )
            actions.append(f'Added {ip_address} to WAF block list')

    except Exception as e:
        actions.append(f'WAF update failed: {str(e)}')

    # Add to Network ACL
    ec2 = boto3.client('ec2')

    try:
        # Find the lowest available rule number
        nacl_id = 'your-nacl-id'
        nacl = ec2.describe_network_acls(NetworkAclIds=[nacl_id])

        used_rules = [
            e['RuleNumber']
            for e in nacl['NetworkAcls'][0]['Entries']
            if e['RuleNumber'] < 32767
        ]

        rule_number = 1
        while rule_number in used_rules:
            rule_number += 1

        # Add deny rule
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=rule_number,
            Protocol='-1',  # All protocols
            RuleAction='deny',
            Egress=False,  # Inbound
            CidrBlock=f'{ip_address}/32'
        )
        actions.append(f'Added NACL rule {rule_number} to block {ip_address}')

    except Exception as e:
        actions.append(f'NACL update failed: {str(e)}')

    return {
        'status': 'blocked',
        'ip_address': ip_address,
        'reason': reason,
        'actions': actions,
        'timestamp': datetime.utcnow().isoformat()
    }
```

## Part 2: Evidence Collection Automation

### Exercise 2.1: Disk Snapshot Automation

```python
def create_forensic_snapshot(instance_id, case_id):
    """Create forensic snapshots of all volumes attached to an instance."""

    ec2 = boto3.client('ec2')

    # Get instance details
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]

    snapshots = []

    for block_device in instance['BlockDeviceMappings']:
        volume_id = block_device['Ebs']['VolumeId']
        device_name = block_device['DeviceName']

        # Create snapshot
        snapshot = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f'IR Forensic - Case {case_id} - {instance_id} - {device_name}',
            TagSpecifications=[{
                'ResourceType': 'snapshot',
                'Tags': [
                    {'Key': 'IR_CaseId', 'Value': case_id},
                    {'Key': 'IR_InstanceId', 'Value': instance_id},
                    {'Key': 'IR_DeviceName', 'Value': device_name},
                    {'Key': 'IR_CreatedAt', 'Value': datetime.utcnow().isoformat()},
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
        'snapshots': snapshots,
        'timestamp': datetime.utcnow().isoformat()
    }

def create_memory_acquisition_ssm(instance_id, s3_bucket, case_id):
    """Use SSM to acquire memory from a running instance."""

    ssm = boto3.client('ssm')

    # Memory acquisition command (Linux with LiME)
    commands = [
        'cd /tmp',
        'sudo insmod /opt/forensics/lime.ko "path=/tmp/memory.lime format=lime"',
        f'aws s3 cp /tmp/memory.lime s3://{s3_bucket}/cases/{case_id}/memory/{instance_id}.lime',
        'rm /tmp/memory.lime'
    ]

    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={
            'commands': commands
        },
        OutputS3BucketName=s3_bucket,
        OutputS3KeyPrefix=f'cases/{case_id}/ssm-output'
    )

    return {
        'command_id': response['Command']['CommandId'],
        'instance_id': instance_id,
        'status': 'memory_acquisition_initiated'
    }
```

### Exercise 2.2: Log Collection Automation

```python
def collect_cloudtrail_evidence(case_id, time_range, s3_bucket):
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

def collect_vpc_flow_logs(case_id, log_group, time_range, s3_bucket):
    """Collect VPC flow logs for investigation."""

    logs = boto3.client('logs')
    s3 = boto3.client('s3')

    # Query CloudWatch Logs Insights
    query = """
    fields @timestamp, srcAddr, dstAddr, srcPort, dstPort,
           protocol, packets, bytes, action
    | sort @timestamp desc
    """

    response = logs.start_query(
        logGroupName=log_group,
        startTime=int(time_range['start'].timestamp()),
        endTime=int(time_range['end'].timestamp()),
        queryString=query
    )

    query_id = response['queryId']

    # Wait for query to complete
    while True:
        result = logs.get_query_results(queryId=query_id)
        if result['status'] == 'Complete':
            break
        time.sleep(1)

    # Save results
    s3.put_object(
        Bucket=s3_bucket,
        Key=f'cases/{case_id}/vpc-flow-logs/flows.json',
        Body=json.dumps(result['results'], default=str),
        ServerSideEncryption='aws:kms'
    )

    return {
        'status': 'collected',
        'case_id': case_id,
        'record_count': len(result['results']),
        's3_path': f's3://{s3_bucket}/cases/{case_id}/vpc-flow-logs/flows.json'
    }
```

### Exercise 2.3: Evidence Integrity

```python
import hashlib

def hash_evidence_file(s3_bucket, s3_key):
    """Calculate and store hash of evidence file."""

    s3 = boto3.client('s3')

    # Get file
    response = s3.get_object(Bucket=s3_bucket, Key=s3_key)
    content = response['Body'].read()

    # Calculate hashes
    hashes = {
        'md5': hashlib.md5(content).hexdigest(),
        'sha256': hashlib.sha256(content).hexdigest(),
        'sha512': hashlib.sha512(content).hexdigest()
    }

    # Store hash file
    hash_key = f'{s3_key}.hashes.json'
    s3.put_object(
        Bucket=s3_bucket,
        Key=hash_key,
        Body=json.dumps({
            'original_file': s3_key,
            'file_size': len(content),
            'hashes': hashes,
            'hash_time': datetime.utcnow().isoformat()
        }),
        ServerSideEncryption='aws:kms'
    )

    return hashes

def create_evidence_chain_of_custody(case_id, evidence_items, s3_bucket):
    """Create chain of custody record for evidence."""

    s3 = boto3.client('s3')
    sts = boto3.client('sts')

    # Get caller identity
    identity = sts.get_caller_identity()

    custody_record = {
        'case_id': case_id,
        'created_at': datetime.utcnow().isoformat(),
        'created_by': identity['Arn'],
        'evidence_items': [],
        'custody_chain': [{
            'action': 'created',
            'timestamp': datetime.utcnow().isoformat(),
            'actor': identity['Arn'],
            'notes': 'Initial evidence collection'
        }]
    }

    for item in evidence_items:
        # Calculate hash
        hashes = hash_evidence_file(s3_bucket, item['s3_key'])

        custody_record['evidence_items'].append({
            'item_id': str(uuid.uuid4()),
            'description': item['description'],
            's3_path': f"s3://{s3_bucket}/{item['s3_key']}",
            'hashes': hashes,
            'collected_at': item.get('collected_at', datetime.utcnow().isoformat())
        })

    # Save custody record
    s3.put_object(
        Bucket=s3_bucket,
        Key=f'cases/{case_id}/chain_of_custody.json',
        Body=json.dumps(custody_record),
        ServerSideEncryption='aws:kms'
    )

    return custody_record
```

## Part 3: Orchestration Workflows

### Exercise 3.1: Step Functions Workflow

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
        },
        {
          "StartAt": "NotifyTeam",
          "States": {
            "NotifyTeam": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:region:account:function:ir-notify",
              "Parameters": {
                "channel": "critical",
                "message.$": "$.alert"
              },
              "End": true
            }
          }
        }
      ],
      "Next": "CollectEvidence"
    },
    "HighResponse": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:ir-high-response",
      "Next": "CollectEvidence"
    },
    "StandardResponse": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:ir-standard-response",
      "Next": "CreateTicket"
    },
    "CollectEvidence": {
      "Type": "Parallel",
      "Branches": [
        {
          "StartAt": "CollectCloudTrail",
          "States": {
            "CollectCloudTrail": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:region:account:function:ir-collect-cloudtrail",
              "End": true
            }
          }
        },
        {
          "StartAt": "CollectFlowLogs",
          "States": {
            "CollectFlowLogs": {
              "Type": "Task",
              "Resource": "arn:aws:lambda:region:account:function:ir-collect-flowlogs",
              "End": true
            }
          }
        }
      ],
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

### Exercise 3.2: EventBridge Integration

```python
def setup_detection_automation():
    """Set up EventBridge rules for automated response."""

    events = boto3.client('events')

    # Rule for GuardDuty findings
    events.put_rule(
        Name='IR-GuardDuty-HighSeverity',
        EventPattern=json.dumps({
            "source": ["aws.guardduty"],
            "detail-type": ["GuardDuty Finding"],
            "detail": {
                "severity": [{"numeric": [">=", 7]}]
            }
        }),
        State='ENABLED',
        Description='Trigger IR automation for high severity GuardDuty findings'
    )

    # Target: Step Functions workflow
    events.put_targets(
        Rule='IR-GuardDuty-HighSeverity',
        Targets=[{
            'Id': 'IRWorkflow',
            'Arn': 'arn:aws:states:region:account:stateMachine:ir-workflow',
            'RoleArn': 'arn:aws:iam::account:role/EventBridgeIRRole',
            'InputTransformer': {
                'InputPathsMap': {
                    'findingId': '$.detail.id',
                    'severity': '$.detail.severity',
                    'type': '$.detail.type',
                    'resource': '$.detail.resource'
                },
                'InputTemplate': json.dumps({
                    'alert_id': '<findingId>',
                    'severity': '<severity>',
                    'alert_type': '<type>',
                    'affected_resource': '<resource>',
                    'source': 'guardduty'
                })
            }
        }]
    )

    # Rule for Security Hub findings
    events.put_rule(
        Name='IR-SecurityHub-Critical',
        EventPattern=json.dumps({
            "source": ["aws.securityhub"],
            "detail-type": ["Security Hub Findings - Imported"],
            "detail": {
                "findings": {
                    "Severity": {
                        "Label": ["CRITICAL"]
                    }
                }
            }
        }),
        State='ENABLED'
    )

    return {'status': 'rules_created'}
```

### Exercise 3.3: Multi-Cloud Orchestration

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

class MultiCloudIROrchestrator:
    """Orchestrate IR actions across multiple cloud providers."""

    def __init__(self):
        self.aws = boto3.Session()
        self.gcp_project = 'your-project'
        self.azure_subscription = 'your-subscription'

    def isolate_resource(self, cloud, resource_id, resource_type):
        """Isolate a resource in any cloud."""

        handlers = {
            'aws': self._isolate_aws,
            'gcp': self._isolate_gcp,
            'azure': self._isolate_azure
        }

        handler = handlers.get(cloud)
        if handler:
            return handler(resource_id, resource_type)
        else:
            raise ValueError(f'Unknown cloud provider: {cloud}')

    def _isolate_aws(self, resource_id, resource_type):
        if resource_type == 'ec2':
            return isolate_ec2_instance(resource_id, 'isolation-sg-id', 'IR')
        elif resource_type == 'iam_user':
            return revoke_iam_credentials(resource_id)
        elif resource_type == 'iam_role':
            return invalidate_role_sessions(resource_id)

    def _isolate_gcp(self, resource_id, resource_type):
        """GCP isolation logic."""
        # Implementation for GCP
        pass

    def _isolate_azure(self, resource_id, resource_type):
        """Azure isolation logic."""
        # Implementation for Azure
        pass

    def parallel_containment(self, targets):
        """Execute containment actions in parallel across clouds."""

        results = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(
                    self.isolate_resource,
                    target['cloud'],
                    target['resource_id'],
                    target['resource_type']
                ): target
                for target in targets
            }

            for future in as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    results.append({
                        'target': target,
                        'status': 'success',
                        'result': result
                    })
                except Exception as e:
                    results.append({
                        'target': target,
                        'status': 'failed',
                        'error': str(e)
                    })

        return results
```

## Part 4: Detection-to-Response Pipeline

### Exercise 4.1: Alert to Automation

```python
def handle_xdr_alert(alert):
    """Handle alert from XDR platform."""

    # Parse alert
    affected_user = alert.get('user_identity_name')
    source_ip = alert.get('source_ip')
    action_count = alert.get('action_count')

    # Determine response based on alert type
    response_actions = []

    if action_count > 50:
        # Critical - immediate containment
        response_actions.append({
            'action': 'revoke_credentials',
            'target': affected_user,
            'priority': 'immediate'
        })
        response_actions.append({
            'action': 'block_ip',
            'target': source_ip,
            'priority': 'immediate'
        })
    elif action_count > 20:
        # High - containment with notification
        response_actions.append({
            'action': 'revoke_credentials',
            'target': affected_user,
            'priority': 'high'
        })
        response_actions.append({
            'action': 'notify',
            'target': 'security-team',
            'priority': 'high'
        })
    else:
        # Medium - investigation
        response_actions.append({
            'action': 'create_investigation',
            'target': affected_user,
            'priority': 'medium'
        })

    # Execute response
    return execute_response_playbook(response_actions)
```

### Exercise 4.2: Orchestration Platform Integration

```python
class OrchestrationPlatform:
    """Integration with orchestration platforms."""

    def __init__(self, orchestration_url, api_key):
        self.orchestration_url = orchestration_url
        self.api_key = api_key

    def create_incident(self, alert_data):
        """Create incident in orchestration platform."""

        incident = {
            'title': f"Cloud Security Alert - {alert_data['type']}",
            'severity': alert_data['severity'],
            'source': 'cloud-ir-automation',
            'artifacts': [
                {
                    'type': 'ip',
                    'value': alert_data.get('source_ip'),
                    'context': 'source'
                },
                {
                    'type': 'user',
                    'value': alert_data.get('user'),
                    'context': 'affected'
                },
                {
                    'type': 'resource',
                    'value': alert_data.get('resource_id'),
                    'context': 'target'
                }
            ],
            'playbook': self._select_playbook(alert_data['type'])
        }

        response = requests.post(
            f'{self.orchestration_url}/api/incidents',
            headers={'Authorization': f'Bearer {self.api_key}'},
            json=incident
        )

        return response.json()

    def _select_playbook(self, alert_type):
        """Select appropriate playbook based on alert type."""

        playbook_map = {
            'unauthorized_api_call': 'cloud-credential-compromise',
            'data_exfiltration': 'cloud-data-breach',
            'cryptomining': 'cloud-cryptojacking',
            'privilege_escalation': 'cloud-privilege-escalation',
            'malware': 'cloud-malware-infection'
        }

        return playbook_map.get(alert_type, 'cloud-generic-investigation')
```

## Part 5: Testing and Validation

### Exercise 5.1: IR Automation Testing

```python
import pytest
from unittest.mock import patch, MagicMock

class TestIRAutomation:
    """Test IR automation functions."""

    @patch('boto3.client')
    def test_isolate_ec2_instance(self, mock_client):
        """Test EC2 isolation."""
        # Setup mock
        mock_ec2 = MagicMock()
        mock_client.return_value = mock_ec2

        mock_ec2.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'SecurityGroups': [{'GroupId': 'sg-original'}]
                }]
            }]
        }

        # Execute
        result = isolate_ec2_instance(
            'i-12345',
            'sg-isolation',
            'test reason'
        )

        # Verify
        assert result['status'] == 'isolated'
        mock_ec2.modify_instance_attribute.assert_called_once()
        mock_ec2.create_tags.assert_called_once()

    @patch('boto3.client')
    def test_revoke_credentials(self, mock_client):
        """Test credential revocation."""
        mock_iam = MagicMock()
        mock_client.return_value = mock_iam

        mock_iam.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {'AccessKeyId': 'AKIAEXAMPLE1'},
                {'AccessKeyId': 'AKIAEXAMPLE2'}
            ]
        }
        mock_iam.list_mfa_devices.return_value = {'MFADevices': []}

        result = revoke_iam_credentials('testuser')

        assert result['status'] == 'revoked'
        assert len(result['actions_taken']) > 0

def test_workflow_integration():
    """Integration test for full IR workflow."""

    # Create test alert
    test_alert = {
        'type': 'unauthorized_api_call',
        'severity': 'CRITICAL',
        'source_ip': '1.2.3.4',
        'user': 'testuser',
        'resource_id': 'i-12345'
    }

    # Run workflow (in test mode)
    result = run_ir_workflow(test_alert, test_mode=True)

    # Verify all steps completed
    assert result['containment']['status'] == 'success'
    assert result['evidence_collection']['status'] == 'success'
    assert result['notification']['status'] == 'success'
```

## Exercises

### Exercise 1: Build Containment Playbook
Create an automated playbook that:
1. Isolates a compromised EC2 instance
2. Revokes associated IAM credentials
3. Creates forensic snapshots
4. Notifies the security team

### Exercise 2: Evidence Collection Pipeline
Build a pipeline that:
1. Collects CloudTrail logs for affected resources
2. Exports VPC flow logs
3. Creates chain of custody records
4. Calculates evidence hashes

### Exercise 3: Multi-Cloud Response
Design and implement:
1. Detection rule that works across AWS, GCP, Azure
2. Unified response action that isolates resources
3. Cross-cloud evidence collection

### Exercise 4: Testing Framework
Create tests for:
1. Individual containment functions
2. Evidence integrity verification
3. End-to-end workflow execution

## Challenge Questions

1. How do you handle IR automation failures without leaving systems in an inconsistent state?
2. What are the risks of automated containment and how do you mitigate false positives?
3. Design a rollback mechanism for automated IR actions.
4. How would you implement IR automation for a multi-account AWS organization?

## Resources

- [AWS Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/)
- [NIST Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [AWS Step Functions](https://docs.aws.amazon.com/step-functions/)
- [Cloud Security Alliance - Incident Response](https://cloudsecurityalliance.org/research/guidance/)
