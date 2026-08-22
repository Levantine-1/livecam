# GitHub Actions assumes this role via OIDC (short-lived federated tokens)
# instead of a long-lived static IAM user key. The OIDC provider itself is
# account-wide and created once in the core terraform repo -- referenced
# here by its known ARN directly, matching thisper's iam_oidc_role.tf.
locals {
  github_oidc_provider_arn = "arn:aws:iam::975050308029:oidc-provider/token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Scoped to pushes to master specifically, not a bare repo:* wildcard.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:Levantine-1/livecam:ref:refs/heads/master"]
    }
  }
}

resource "aws_iam_role" "github_actions_livecam" {
  name               = "github_actions_livecam"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume_role.json
}

# ecr/route53/s3 statement shape copied from thisper's equivalent policy,
# resource ARNs updated for this repo. No ec2:Describe* statements --
# thisper's exist to read the bastion instance for its Route53 record,
# which route53_records.tf/route_53_delegate_records.tf need here too, so
# those are kept; nothing else here needs broader EC2 access.
resource "aws_iam_role_policy" "github_actions_livecam_policy" {
  name = "github_actions_livecam_policy"
  role = aws_iam_role.github_actions_livecam.id

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetRole",
                "iam:CreateRole",
                "iam:DeleteRole",
                "iam:GetRolePolicy",
                "iam:PutRolePolicy",
                "iam:DeleteRolePolicy",
                "iam:ListRolePolicies",
                "iam:ListAttachedRolePolicies"
            ],
            "Resource": "arn:aws:iam::975050308029:role/github_actions_livecam"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ecr:CreateRepository",
                "ecr:DeleteRepository",
                "ecr:DescribeRepositories",
                "ecr:PutImage",
                "ecr:BatchDeleteImage",
                "ecr:BatchGetImage",
                "ecr:DescribeImages",
                "ecr:GetDownloadUrlForLayer",
                "ecr:ListTagsForResource",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:BatchCheckLayerAvailability"
            ],
            "Resource": "arn:aws:ecr:${var.region}:975050308029:repository/livecam"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeVolumes",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeInstanceCreditSpecifications"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "route53:ListHostedZones",
                "route53:GetHostedZone",
                "route53:ListTagsForResource",
                "route53:ChangeResourceRecordSets",
                "route53:GetChange",
                "route53:ListResourceRecordSets"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::prod-levantine-terraform-bucket/livecam/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": "arn:aws:s3:::prod-levantine-terraform-bucket",
            "Condition": {
                "StringLike": {
                    "s3:prefix": "livecam/*"
                }
            }
        }
    ]
}
EOF
}
