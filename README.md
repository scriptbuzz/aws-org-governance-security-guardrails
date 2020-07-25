# org-governance
Automations and policies applied from the Organization account to enforce best practices

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
