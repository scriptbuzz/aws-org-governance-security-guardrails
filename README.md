# org-governance
 SCP policies I use frequently to apply from AWS Organization account to enforce best practices in sub-accounts. 

- SCP prevents actions against any role starting with OrgSec in sub-accounts

```
    "Statement": [
        {
            "Sid": "PreventOrgSecRoleActions",
            "Effect": "Deny",
            "Action": [
                "*"
            ],
            "Resource": [
                "arn:aws:iam::*:role/OrgSec*"
            ],
            "Condition": {
                "StringNotLike": {
                    "aws:PrincipalARN": "arn:aws:iam::*:role/OrgSec*"
                }
            }
        }
    ]
}
```

- SCP prevents creation of IAM users with login profies in sub-accounts. This ensures your corporate directory is the single source of truth for users with login credentials.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PreventIAMUserWithLoginActions",
            "Effect": "Deny",
            "Action": [
                "iam:ChangePassword",
                "iam:CreateLoginProfile",
                "iam:UpdateLoginProfile",
                "iam:UpdateAccountPasswordPolicy"
            ],
            "Resource": [
                "*"
            ]
     }]
}
```

- SCP to protect CloudTrails in sub-accounts from being tampered with.

```
{
            "Sid": "ProtectCloudTrails",
            "Effect": "Deny",
            "Action": [
                "cloudtrail:DeleteTrail",
                "cloudtrail:StopLogging",
		"cloudtrail:PutEventSelectors",
                "cloudtrail:UpdateTrail"
            ],
            "Resource": [
                "arn:aws:cloudtrail:*:*:trail/somecloudtrail"
            ]
}
```
- SCP to prevent public access to S3 in sub-accounts
```
{
            "Sid": "PreventAllS3PublicAccess",
            "Action": [
                "s3:PutAccountPublicAccessBlock"
            ],
            "Resource": "*",
            "Effect": "Deny"
}
```
- SCP to protect sub-accounts from leaving the root Organization account
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ProtectAgainstLeavingOrganization",
            "Effect": "Deny",
            "Action": [
                "organizations:LeaveOrganization"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

- SCP to protect GuardDuty in sub-accounts
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": [ 
                "guardduty:AcceptInvitation",
                "guardduty:ArchiveFindings",
                "guardduty:CreateDetector",
                "guardduty:CreateFilter",
                "guardduty:CreateIPSet",
                "guardduty:CreateMembers",
                "guardduty:CreatePublishingDestination",
                "guardduty:CreateSampleFindings",
                "guardduty:CreateThreatIntelSet",
                "guardduty:DeclineInvitations",
                "guardduty:DeleteDetector",
                "guardduty:DeleteFilter",
                "guardduty:DeleteInvitations",
                "guardduty:DeleteIPSet",
                "guardduty:DeleteMembers",
                "guardduty:DeletePublishingDestination",
                "guardduty:DeleteThreatIntelSet",
                "guardduty:DisassociateFromMasterAccount",
                "guardduty:DisassociateMembers",
                "guardduty:InviteMembers",
                "guardduty:StartMonitoringMembers",
                "guardduty:StopMonitoringMembers",
                "guardduty:TagResource",
                "guardduty:UnarchiveFindings",
                "guardduty:UntagResource",
                "guardduty:UpdateDetector",
                "guardduty:UpdateFilter",
                "guardduty:UpdateFindingsFeedback",
                "guardduty:UpdateIPSet",
                "guardduty:UpdatePublishingDestination",
                "guardduty:UpdateThreatIntelSet"
            ],      
            "Resource": "*"
        }
    ]
}
```
- SCP to protect VPC Flowlogs
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:DeleteFlowLogs",
        "logs:DeleteLogGroup",
        "logs:DeleteLogStream"
      ],
      "Resource": "*"
    }
  ]
 }
```
- SCP to protect Confg in sub-accounts
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "config:DeleteConfigRule",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:StopConfigurationRecorder"
      ],
      "Resource": "*"
    }
  ]
}
```
- SCP to protect a private VPC from having an Internet Gateway attached to it
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:AttachInternetGateway",
        "ec2:CreateInternetGateway",
        "ec2:CreateEgressOnlyInternetGateway",
        "ec2:CreateVpcPeeringConnection",
        "ec2:AcceptVpcPeeringConnection",
        "globalaccelerator:Create*",
        "globalaccelerator:Update*"
      ],
      "Resource": "*"
    }
  ]
}
```
- SCP prevents api actions in regions not supported by your project, with the exception of global services. In this policy, only regions us-east-1 and us-east-2 are supported
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyAllOutsideMyRegions",
            "Effect": "Deny",
            "NotAction": [
               "a4b:*", "artifact:*", "aws-portal:*",
                "budgets:*",
                "ce:*", "chime:*", "cloudfront:*", "cur:*",
                "datapipeline:GetAccountLimits", "directconnect:",
                "globalaccelerator:*",
                "health:*",
                "iam:*", "importexport:*",
                "mobileanalytics:*",
                "organizations:*",
                "resource-groups:*", "route53:*", "route53domains:*",
                "s3:GetBucketLocation", "s3:ListAllMyBuckets", "shield:*", "support:*",
                "tag:*", "trustedadvisor:*",
                "waf:*",
                "wellarchitected:*"
            ],
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "aws:RequestedRegion": [
                        "us-east-1",
                        "us-east-2"
                    ]
                }
            }
        }
    ]
}
```
- SCP prevents changes to specific protected IAM roles in sub-account, except if the changes are performed by an admin role you designate to make those changes
```
{    
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyChangesToRoleExceptByAdminRole",
      "Effect": "Deny",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:DeleteRole",
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeleteRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:UpdateRole",
        "iam:UpdateRoleDescription"
      ],
      "Resource": [
        "arn:aws:iam::*:role/SomeProtectedRole"
      ],
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalARN":"arn:aws:iam::*:role/MyAdminRole"
        }
      }
    }
  ]
}

```
- SCP enforces EC2 instance type in sub-accounts. This could be applied to sandbox accounts to control costs.
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireMicroInstanceType",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals":{               	
          "ec2:InstanceType":"t2.micro"
        }
      }
    }
  ]
} 

```
- SCP to prevent stopping EC2 instaces without MFA authintication. This can be applied to production accounts with critical workloads.
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyStopAndTerminateWhenMFAIsNotPresent",
      "Effect": "Deny",
      "Action": [
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*",
      "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": false}}
    }
  ]
} 
```

- SCP to prevent creation of root access keys in sub-accounts
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Example",
            "Effect": "Deny",
            "Action": "iam:CreateAccessKey",
            "Resource": [
                "*"
            ],
            "Condition": {
                "StringLike": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::*:root"
                    ]
                }
            }
        }
    ]
}
```
- SCP to prevent creation of root users in sub-accounts
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Example",
      "Effect": "Deny",
      "Action": "*",
      "Resource": [
        "*"
      ],
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:root"
          ]
        }
      }
    }
  ]
}
```
- SCP to prevent actions from root user in sub-accounts
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Example",
      "Effect": "Deny",
      "Action": "*",
      "Resource": [
        "*"
      ],
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:root"
          ]
        }
      }
    }
  ]
}
```
- SCP to prevent cross-region S3 replication if, for example, compliance requirements do not permit S3 data leaving your default region.
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Example",
            "Effect": "Deny",
            "Action": [
                "s3:PutReplicationConfiguration"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```
- SCP to prevent deletion of S3 objects without MFA in sub-accounts. Can be applies to mission critical S3 buckets
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Example",
            "Effect": "Deny",
            "Action": [
                "s3:DeleteObject",
                "s3:DeleteBucket"
            ],
            "Resource": [
                "*"
            ],
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": [
                        "false"
                    ]
                }
            }
        }
    ]
}
```
- SCP pevents changes to your protected IAM roles unless the changes are performed by your admin role.
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Example",
      "Effect": "Deny",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeleteRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:UpdateRole",
        "iam:UpdateRoleDescription"
      ],
      "Resource": [
        "arn:aws:iam::*:role/my-role*",
        "arn:aws:iam::*:role/some-role*"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN":"arn:aws:iam::*:role/MyAdminRole"
        }
      }
    }
  ]
}

```
