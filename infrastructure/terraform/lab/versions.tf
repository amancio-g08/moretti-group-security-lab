terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # State stays on the operator's machine (Phase 4 decision): no remote backend to pay for or
  # secure. terraform.tfstate is ignored by Git because it can contain sensitive attributes.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Stack     = "lab"
    }
  }
}
