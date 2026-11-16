"""IaC rule pack: Terraform, AWS and Terragrunt validators and the HCL scanner."""

import pytest

from governance.validators import BUILTIN, FileSet
from governance.validators.terraform import parse_hcl


def run(validator_id, path, text, extra=None):
    files = {path: text, **(extra or {})}
    return list(BUILTIN[validator_id].file_check(path, text, FileSet(files)))


def module(source, version=None):
    version_line = f'\n  version = "{version}"' if version else ""
    return f'module "m" {{\n  source = "{source}"{version_line}\n}}\n'


def resource(rtype, body, name="r"):
    return f'resource "{rtype}" "{name}" {{\n{body}\n}}\n'


SG_INGRESS = """\
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = %s
    to_port     = %s
    protocol    = "%s"
    cidr_blocks = ["%s"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

EKS = """\
resource "aws_eks_cluster" "c" {
  name = "c"
  vpc_config {
    subnet_ids = var.subnets
%s
  }
}
"""

LISTENER = """\
resource "aws_lb_listener" "l" {
  load_balancer_arn = aws_lb.a.arn
  port              = %s
  protocol          = "%s"
%s
}
"""

REDIRECT = """\
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }"""

FORWARD = """\
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.t.arn
  }"""

DB_PROTECTED = "  deletion_protection = true\n  backup_retention_period = 14"

ROOT_HCL = """\
terraform_version_constraint  = ">= 1.9, < 2.0"
terragrunt_version_constraint = ">= 0.80"

remote_state {
  backend = "s3"
  config = {
    bucket       = "acme-state"
    key          = "${path_relative_to_include()}/terraform.tfstate"
    region       = "eu-central-1"
    encrypt      = true
    use_lockfile = true
  }
}
"""

CASES = [
    # TF-003 module pinning
    ("terraform-module-pinning", "main.tf", module("./modules/vpc"), 0),
    ("terraform-module-pinning", "main.tf", module("../shared/vpc"), 0),
    ("terraform-module-pinning", "main.tf", module("terraform-aws-modules/vpc/aws"), 1),
    ("terraform-module-pinning", "main.tf", module("terraform-aws-modules/vpc/aws", "~> 5.8"), 0),
    ("terraform-module-pinning", "main.tf", module("app.terraform.io/acme/vpc/aws"), 1),
    ("terraform-module-pinning", "main.tf", module("app.terraform.io/acme/vpc/aws", "1.2.0"), 0),
    ("terraform-module-pinning", "main.tf", module("git::https://example.com/vpc.git"), 1),
    ("terraform-module-pinning", "main.tf", module("git::https://example.com/vpc.git?ref=v1.2.0"), 0),
    ("terraform-module-pinning", "main.tf", module("git::https://example.com/vpc.git?ref=main"), 1),
    ("terraform-module-pinning", "main.tf", module("git::ssh://git@example.com/vpc.git?ref=HEAD"), 1),
    ("terraform-module-pinning", "main.tf", module("github.com/acme/modules//vpc?ref=master"), 1),
    ("terraform-module-pinning", "main.tf", module("github.com/acme/modules//vpc?ref=3f1c2a9"), 0),
    ("terraform-module-pinning", "main.tf", module("git@github.com:acme/vpc.git"), 1),
    ("terraform-module-pinning", "main.tf", module("bitbucket.org/acme/vpc?depth=1&ref=develop"), 1),
    ("terraform-module-pinning", "main.tf", module("s3::https://s3.amazonaws.com/acme/vpc.zip"), 1),
    ("terraform-module-pinning", "main.tf", module("s3::https://s3.amazonaws.com/acme/vpc-1.4.0.zip"), 0),
    ("terraform-module-pinning", "main.tf", module("https://example.com/vpc-module.zip"), 1),
    ("terraform-module-pinning", "main.tf", '# module "x" {\n#   source = "acme/vpc/aws"\n# }\n', 0),
    # TF-004 sensitive values
    ("terraform-sensitive-values", "variables.tf", 'variable "db_password" {\n  type = string\n}\n', 1),
    (
        "terraform-sensitive-values",
        "variables.tf",
        'variable "db_password" {\n  type      = string\n  sensitive = true\n}\n',
        0,
    ),
    ("terraform-sensitive-values", "variables.tf", 'variable "api_token" {\n  ephemeral = true\n}\n', 0),
    ("terraform-sensitive-values", "variables.tf", 'variable "github_token" {}\n', 1),
    ("terraform-sensitive-values", "variables.tf", 'variable "db_secret_arn" {\n  type = string\n}\n', 0),
    ("terraform-sensitive-values", "variables.tf", 'variable "region" {\n  type = string\n}\n', 0),
    ("terraform-sensitive-values", "outputs.tf", 'output "client_secret" {\n  value = x.secret\n}\n', 1),
    (
        "terraform-sensitive-values",
        "outputs.tf",
        'output "client_secret" {\n  value     = x.secret\n  sensitive = true\n}\n',
        0,
    ),
    ("terraform-sensitive-values", "rds.tf", resource("aws_db_instance", "  password = var.db_password"), 1),
    ("terraform-sensitive-values", "rds.tf", resource("aws_db_instance", "  manage_master_user_password = true"), 0),
    ("terraform-sensitive-values", "rds.tf", resource("aws_db_instance", "  password_wo = var.pw"), 0),
    ("terraform-sensitive-values", "rds.tf", resource("aws_rds_cluster", '  master_password = "x"'), 1),
    ("terraform-sensitive-values", "rds.tf", resource("aws_docdb_cluster", "  master_password = var.pw"), 1),
    ("terraform-sensitive-values", "rds.tf", resource("aws_redshift_cluster", "  master_password = var.pw"), 1),
    ("terraform-sensitive-values", "rds.tf", resource("aws_redshift_cluster", "  manage_master_password = true"), 0),
    # TF-006 default tags
    ("terraform-aws-default-tags", "providers.tf", 'provider "aws" {\n  region = "eu-west-1"\n}\n', 1),
    (
        "terraform-aws-default-tags",
        "providers.tf",
        'provider "aws" {\n  default_tags {\n    tags = {\n      Owner       = "payments"\n'
        "      Environment = var.env\n    }\n  }\n}\n",
        0,
    ),
    (
        "terraform-aws-default-tags",
        "providers.tf",
        'provider "aws" {\n  default_tags {\n    tags = { owner = "payments" }\n  }\n}\n',
        1,
    ),
    (
        "terraform-aws-default-tags",
        "providers.tf",
        'provider "aws" {\n  default_tags {\n    tags = var.tags\n  }\n}\n',
        0,
    ),
    ("terraform-aws-default-tags", "providers.tf", 'provider "google" {\n  project = "x"\n}\n', 0),
    # AWS-004 security groups
    ("terraform-sg-open-ingress", "sg.tf", SG_INGRESS % (22, 22, "tcp", "0.0.0.0/0"), 1),
    ("terraform-sg-open-ingress", "sg.tf", SG_INGRESS % (22, 22, "tcp", "10.0.0.0/8"), 0),
    ("terraform-sg-open-ingress", "sg.tf", SG_INGRESS % (443, 443, "tcp", "0.0.0.0/0"), 0),
    ("terraform-sg-open-ingress", "sg.tf", SG_INGRESS % (80, 80, "tcp", "0.0.0.0/0"), 0),
    ("terraform-sg-open-ingress", "sg.tf", SG_INGRESS % (0, 65535, "tcp", "0.0.0.0/0"), 1),
    ("terraform-sg-open-ingress", "sg.tf", SG_INGRESS % (5000, 6000, "tcp", "0.0.0.0/0"), 1),
    ("terraform-sg-open-ingress", "sg.tf", SG_INGRESS % (0, 0, "-1", "0.0.0.0/0"), 1),
    ("terraform-sg-open-ingress", "sg.tf", SG_INGRESS % (8, 0, "icmp", "0.0.0.0/0"), 0),
    (
        "terraform-sg-open-ingress",
        "sg.tf",
        (SG_INGRESS % (3389, 3389, "tcp", "::/0")).replace("cidr_", "ipv6_cidr_"),
        1,
    ),
    (
        "terraform-sg-open-ingress",
        "sg.tf",
        resource(
            "aws_security_group_rule",
            '  type        = "ingress"\n  from_port   = 5432\n  to_port     = 5432\n'
            '  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]',
        ),
        1,
    ),
    (
        "terraform-sg-open-ingress",
        "sg.tf",
        resource(
            "aws_security_group_rule",
            '  type        = "egress"\n  from_port   = 5432\n  to_port     = 5432\n'
            '  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]',
        ),
        0,
    ),
    (
        "terraform-sg-open-ingress",
        "sg.tf",
        resource(
            "aws_vpc_security_group_ingress_rule",
            '  cidr_ipv4   = "0.0.0.0/0"\n  from_port   = 6379\n  to_port     = 6379\n  ip_protocol = "tcp"',
        ),
        1,
    ),
    (
        "terraform-sg-open-ingress",
        "sg.tf",
        resource("aws_vpc_security_group_ingress_rule", '  cidr_ipv6   = "::/0"\n  ip_protocol = "-1"'),
        1,
    ),
    (
        "terraform-sg-open-ingress",
        "sg.tf",
        resource(
            "aws_vpc_security_group_ingress_rule",
            '  cidr_ipv4   = "0.0.0.0/0"\n  from_port   = 443\n  to_port     = 443\n  ip_protocol = "tcp"',
        ),
        0,
    ),
    # AWS-005 public endpoints
    ("terraform-public-endpoints", "rds.tf", resource("aws_db_instance", "  publicly_accessible = true"), 1),
    ("terraform-public-endpoints", "rds.tf", resource("aws_db_instance", "  publicly_accessible = false"), 0),
    ("terraform-public-endpoints", "mq.tf", resource("aws_mq_broker", "  publicly_accessible = true"), 1),
    ("terraform-public-endpoints", "eks.tf", EKS % "", 1),
    ("terraform-public-endpoints", "eks.tf", EKS % "    endpoint_public_access = false", 0),
    ("terraform-public-endpoints", "eks.tf", EKS % '    public_access_cidrs = ["203.0.113.0/24"]', 0),
    ("terraform-public-endpoints", "eks.tf", EKS % '    public_access_cidrs = ["0.0.0.0/0"]', 1),
    (
        "terraform-public-endpoints",
        "eks.tf",
        EKS % '    endpoint_public_access = true\n    public_access_cidrs = ["198.51.100.10/32"]',
        0,
    ),
    # AWS-006 CloudTrail
    ("terraform-cloudtrail", "ct.tf", resource("aws_cloudtrail", '  name = "t"\n  s3_bucket_name = "b"'), 1),
    (
        "terraform-cloudtrail",
        "ct.tf",
        resource(
            "aws_cloudtrail",
            "  is_multi_region_trail = true\n  enable_log_file_validation = true\n  kms_key_id = aws_kms_key.ct.arn",
        ),
        0,
    ),
    (
        "terraform-cloudtrail",
        "ct.tf",
        resource("aws_cloudtrail", "  is_multi_region_trail = true\n  enable_log_file_validation = true"),
        1,
    ),
    # AWS-007 KMS rotation
    ("terraform-kms-rotation", "kms.tf", resource("aws_kms_key", '  description = "app"'), 1),
    ("terraform-kms-rotation", "kms.tf", resource("aws_kms_key", "  enable_key_rotation = true"), 0),
    ("terraform-kms-rotation", "kms.tf", resource("aws_kms_key", "  enable_key_rotation = false"), 1),
    (
        "terraform-kms-rotation",
        "kms.tf",
        resource("aws_kms_key", '  customer_master_key_spec = "RSA_2048"\n  key_usage = "SIGN_VERIFY"'),
        0,
    ),
    ("terraform-kms-rotation", "kms.tf", resource("aws_kms_key", '  customer_master_key_spec = "HMAC_256"'), 0),
    (
        "terraform-kms-rotation",
        "kms.tf",
        resource("aws_kms_key", '  customer_master_key_spec = "SYMMETRIC_DEFAULT"'),
        1,
    ),
    ("terraform-kms-rotation", "kms.tf", resource("aws_kms_key", "  custom_key_store_id = var.store"), 0),
    # AWS-008 IAM static keys
    ("terraform-iam-static-keys", "iam.tf", resource("aws_iam_access_key", "  user = aws_iam_user.ci.name"), 1),
    ("terraform-iam-static-keys", "iam.tf", resource("aws_iam_user_login_profile", "  user = aws_iam_user.u.name"), 1),
    ("terraform-iam-static-keys", "iam.tf", resource("aws_iam_role", "  name = aws_iam_user.ci.name"), 0),
    # AWS-009 data protection
    ("terraform-data-protection", "rds.tf", resource("aws_db_instance", '  engine = "postgres"'), 1),
    ("terraform-data-protection", "rds.tf", resource("aws_db_instance", DB_PROTECTED), 0),
    (
        "terraform-data-protection",
        "rds.tf",
        resource("aws_rds_cluster", "  deletion_protection = true\n  backup_retention_period = 3"),
        1,
    ),
    ("terraform-data-protection", "rds.tf", resource("aws_rds_cluster", DB_PROTECTED), 0),
    (
        "terraform-data-protection",
        "rds.tf",
        resource("aws_db_instance", "  deletion_protection = true\n  replicate_source_db = aws_db_instance.p.arn"),
        0,
    ),
    ("terraform-data-protection", "ddb.tf", resource("aws_dynamodb_table", '  hash_key = "id"'), 1),
    (
        "terraform-data-protection",
        "ddb.tf",
        resource(
            "aws_dynamodb_table",
            "  deletion_protection_enabled = true\n  point_in_time_recovery {\n    enabled = true\n  }",
        ),
        0,
    ),
    (
        "terraform-data-protection",
        "ddb.tf",
        resource(
            "aws_dynamodb_table",
            "  deletion_protection_enabled = true\n  point_in_time_recovery {\n    enabled = false\n  }",
        ),
        1,
    ),
    # AWS-010 load balancer listeners
    ("terraform-lb-https", "lb.tf", LISTENER % (80, "HTTP", FORWARD), 1),
    ("terraform-lb-https", "lb.tf", LISTENER % (80, "HTTP", REDIRECT), 0),
    ("terraform-lb-https", "lb.tf", LISTENER % (443, "HTTPS", FORWARD), 1),
    (
        "terraform-lb-https",
        "lb.tf",
        LISTENER % (443, "HTTPS", '  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n' + FORWARD),
        0,
    ),
    (
        "terraform-lb-https",
        "lb.tf",
        (LISTENER % (8443, "TLS", FORWARD)).replace("aws_lb_listener", "aws_alb_listener"),
        1,
    ),
    ("terraform-lb-https", "lb.tf", LISTENER % (5432, "TCP", FORWARD), 0),
    # TG-001 source pinning
    ("terragrunt-source-pinning", "live/vpc/terragrunt.hcl", 'terraform {\n  source = "../../modules/vpc"\n}\n', 0),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "git::https://github.com/acme/modules.git//vpc?ref=v1.0.0"\n}\n',
        0,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "git::https://github.com/acme/modules.git//vpc"\n}\n',
        1,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "git::git@github.com:acme/modules.git//vpc?ref=main"\n}\n',
        1,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "tfr:///terraform-aws-modules/vpc/aws"\n}\n',
        1,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "tfr:///terraform-aws-modules/vpc/aws?version=5.8.1"\n}\n',
        0,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source  = "tfr:///terraform-aws-modules/vpc/aws"\n  version = "5.8.1"\n}\n',
        0,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "${include.root.locals.base}//vpc?ref=v1.2.0"\n}\n',
        0,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "${include.root.locals.base}//vpc?ref=main"\n}\n',
        1,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "${include.root.locals.base}//vpc"\n}\n',
        0,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'locals {\n  base = "git::https://github.com/acme/modules.git"\n}\n'
        'terraform {\n  source = "${local.base}//vpc"\n}\n',
        1,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'locals {\n  base = "git::https://github.com/acme/modules.git"\n  version = "v2.0.1"\n}\n'
        'terraform {\n  source = "${local.base}//vpc?ref=${local.version}"\n}\n',
        0,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "git::https://github.com/acme/modules.git//vpc?ref=${local.version}"\n}\n',
        0,
    ),
    (
        "terragrunt-source-pinning",
        "live/vpc/terragrunt.hcl",
        'terraform {\n  source = "${get_repo_root()}/modules/vpc"\n}\n',
        0,
    ),
    # TG-002 remote state
    ("terragrunt-remote-state", "root.hcl", ROOT_HCL, 0),
    ("terragrunt-remote-state", "root.hcl", ROOT_HCL.replace("encrypt      = true", "encrypt = false"), 1),
    ("terragrunt-remote-state", "root.hcl", ROOT_HCL.replace("use_lockfile = true", 'dynamodb_table = "locks"'), 0),
    ("terragrunt-remote-state", "root.hcl", ROOT_HCL.replace("    use_lockfile = true\n", ""), 1),
    (
        "terragrunt-remote-state",
        "root.hcl",
        'remote_state {\n  backend = "s3"\n  config {\n    bucket = "s"\n    encrypt = true\n'
        '    dynamodb_table = "locks"\n  }\n}\n',
        0,
    ),
    (
        "terragrunt-remote-state",
        "root.hcl",
        'remote_state {\n  backend = "s3"\n  config {\n    bucket = "s"\n  }\n}\n',
        1,
    ),
    (
        "terragrunt-remote-state",
        "root.hcl",
        'remote_state {\n  backend = "gcs"\n  config = {\n    bucket = "s"\n  }\n}\n',
        0,
    ),
    (
        "terragrunt-remote-state",
        "root.hcl",
        'remote_state = {\n  backend = "s3"\n  config = { bucket = "s", encrypt = true }\n}\n',
        1,
    ),
    ("terragrunt-remote-state", "root.hcl", 'remote_state {\n  backend = "s3"\n  config = local.state\n}\n', 0),
    # TG-003 version constraints
    ("terragrunt-version-constraints", "root.hcl", ROOT_HCL, 0),
    ("terragrunt-version-constraints", "root.hcl", 'locals {\n  region = "eu-west-1"\n}\n', 1),
    ("terragrunt-version-constraints", "live/terragrunt.hcl", ROOT_HCL.split("\n\n", 1)[1], 1),
    (
        "terragrunt-version-constraints",
        "live/terragrunt.hcl",
        'include "root" {\n  path = find_in_parent_folders("root.hcl")\n}\n' + ROOT_HCL.split("\n\n", 1)[1],
        0,
    ),
    (
        "terragrunt-version-constraints",
        "live/vpc/terragrunt.hcl",
        'include "root" {\n  path = find_in_parent_folders("root.hcl")\n}\n',
        0,
    ),
    # TG-004 mock outputs
    (
        "terragrunt-mock-outputs",
        "live/app/terragrunt.hcl",
        'dependency "vpc" {\n  config_path = "../vpc"\n  mock_outputs = {\n    vpc_id = "vpc-mock"\n  }\n}\n',
        1,
    ),
    (
        "terragrunt-mock-outputs",
        "live/app/terragrunt.hcl",
        'dependency "vpc" {\n  config_path = "../vpc"\n  mock_outputs = {\n    vpc_id = "vpc-mock"\n  }\n'
        '  mock_outputs_allowed_terraform_commands = ["validate", "plan"]\n}\n',
        0,
    ),
    (
        "terragrunt-mock-outputs",
        "live/app/terragrunt.hcl",
        'dependency "vpc" {\n  config_path = "../vpc"\n  mock_outputs = { vpc_id = "vpc-mock" }\n'
        '  mock_outputs_allowed_terraform_commands = ["validate", "plan", "apply"]\n}\n',
        1,
    ),
    (
        "terragrunt-mock-outputs",
        "live/app/terragrunt.hcl",
        'dependency "vpc" {\n  config_path = "../vpc"\n}\n',
        0,
    ),
]


@pytest.mark.parametrize(("vid", "path", "text", "expected"), CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_iac_validator(vid, path, text, expected):
    assert len(run(vid, path, text)) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("terraform.tfstate", 1),
        ("envs/prod/terraform.tfstate.backup", 1),
        ("plan.tfplan", 1),
        ("tfplan", 1),
        ("out/plan.tfplan.json", 1),
        ("main.tf", 0),
        ("README.md", 0),
    ],
)
def test_state_files(path, expected):
    v = BUILTIN["terraform-state-files"]
    findings = list(v.file_check(path, '{"version": 4}', FileSet({path: '{"version": 4}'}))) if v.handles(path) else []
    assert len(findings) == expected
    if findings:
        assert findings[0].line_start == 1
        assert "version" not in findings[0].snippet


def test_nested_ingress_finding_points_at_the_ingress_block():
    [finding] = run("terraform-sg-open-ingress", "sg.tf", SG_INGRESS % (22, 22, "tcp", "0.0.0.0/0"))
    assert finding.line_start == 3
    assert "port 22" in finding.message


def test_dynamic_and_list_ingress_are_checked():
    dynamic = resource(
        "aws_security_group",
        '  dynamic "ingress" {\n    for_each = var.ports\n    content {\n      from_port   = 3306\n'
        '      to_port     = 3306\n      protocol    = "tcp"\n      cidr_blocks = ["0.0.0.0/0"]\n    }\n  }',
    )
    listed = resource(
        "aws_security_group",
        '  ingress = [{\n    from_port   = 27017\n    to_port     = 27017\n    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }]',
    )
    assert len(run("terraform-sg-open-ingress", "sg.tf", dynamic)) == 1
    assert len(run("terraform-sg-open-ingress", "sg.tf", listed)) == 1


def test_default_tags_resolve_locals_across_module_files():
    provider = 'provider "aws" {\n  default_tags {\n    tags = merge(local.tags, { Environment = var.env })\n  }\n}\n'
    good = 'locals {\n  tags = {\n    Owner = "payments"\n  }\n}\n'
    bad = 'locals {\n  tags = {\n    Team = "payments"\n  }\n}\n'
    assert run("terraform-aws-default-tags", "infra/providers.tf", provider, {"infra/locals.tf": good}) == []
    assert len(run("terraform-aws-default-tags", "infra/providers.tf", provider, {"infra/locals.tf": bad})) == 1


def test_scanner_skips_strings_comments_and_heredocs():
    text = """\
// resource "aws_kms_key" "commented" {}
/* resource "aws_kms_key" "block" {
} */
resource "aws_iam_policy" "p" {
  description = "braces { in a string"
  name        = "p-${var.env}-${lookup(var.m, "k", "}")}"
  policy = <<-EOT
    { "Statement": [{ "Effect": "Allow", "Resource": "}" }] }
  EOT
}
resource "aws_kms_key" "k" {
  enable_key_rotation = true # trailing comment {
}
"""
    blocks = parse_hcl(text).blocks
    assert [(b.kind, b.labels, b.line) for b in blocks] == [
        ("resource", ["aws_iam_policy", "p"], 4),
        ("resource", ["aws_kms_key", "k"], 11),
    ]
    assert blocks[1].get("enable_key_rotation") == "true"
    assert run("terraform-kms-rotation", "kms.tf", text) == []


def test_nested_attribute_does_not_shadow_top_level_one():
    text = LISTENER % (80, "HTTP", REDIRECT)
    [listener] = parse_hcl(text).blocks
    assert listener.get("protocol") == '"HTTP"'
    [action] = listener.nested("default_action")
    assert action.line == 5
    assert action.nested("redirect")[0].get("protocol") == '"HTTPS"'


def test_terragrunt_validators_ignore_packer_and_lock_files():
    text = 'terraform {\n  source = "git::https://example.com/m.git"\n}\n'
    assert run("terragrunt-source-pinning", "images/base.pkr.hcl", text) == []
    assert run("terragrunt-source-pinning", ".terraform.lock.hcl", text) == []


def test_existing_terraform_validators_are_unchanged():
    assert len(run("terraform-encryption-at-rest", "a.tf", resource("aws_ebs_volume", "  size = 10"))) == 1
    assert run("terraform-version-pinning", "a.tf", 'terraform {\n  required_version = ">= 1.9"\n}\n') == []
