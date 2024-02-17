data "aws_iam_policy_document" "ec2_instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_service_connect_role" {
  assume_role_policy = data.aws_iam_policy_document.ec2_instance_assume_role_policy.json
  name               = "EcsClusterServiceConnectTLSRole"
}

resource "aws_iam_role_policy_attachment" "ecs_service_connect_role" {
  role       = aws_iam_role.ecs_service_connect_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRolePolicyForServiceConnectTransportLayerSecurity"
}

resource "aws_acmpca_certificate_authority_certificate" "example" {
  certificate_authority_arn = aws_acmpca_certificate_authority.example.arn

  certificate       = aws_acmpca_certificate.example.certificate
  certificate_chain = aws_acmpca_certificate.example.certificate_chain
}

resource "aws_acmpca_certificate" "example" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.example.arn
  certificate_signing_request = aws_acmpca_certificate_authority.example.certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  template_arn = "arn:${data.aws_partition.current.partition}:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 1
  }
}

resource "aws_acmpca_certificate_authority" "example" {
  type       = "ROOT"
  usage_mode = "SHORT_LIVED_CERTIFICATE"


  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = "example.com"
    }
  }
  tags = {
    AmazonECSManaged = "true"
  }
}

data "aws_caller_identity" "current" {}

module "secrets_kms_key" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 2.1"

  description = "Customer managed key to encrypt ECS Service Connect Secret on Managed Secrets"

  # Policy
  key_administrators = [
    data.aws_caller_identity.current.arn
  ]

  tags = local.tags
}

