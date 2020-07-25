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


