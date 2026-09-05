package cdk_preflight

import rego.v1

_pf_smkk_url := "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html"

_pf_smkk_fix := "Use alias/aws/secretsmanager, or a customer managed key (Ref / ARN) in the same region"

# [partition, service, region, account, resource...] of a literal ARN; undefined otherwise
_pf_smkk_arn(s) := parts if {
	is_string(s)
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) >= 6
}

# Region comparison needs the deploy region (enforce mode only).
violation contains make_diag_full("pf-secretsmanager-kms-key", "ERROR", name,
	"Properties.KmsKeyId",
	sprintf("KMS key is in '%s' but the secret deploys to '%s'; CreateSecret fails with \"The operation failed because of an invalid KMS key: Invalid arn %s\"", [parts[3], region, parts[3]]),
	_pf_smkk_fix, _pf_smkk_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::SecretsManager::Secret")
	parts := _pf_smkk_arn(resolve(name, "Properties.KmsKeyId"))
	parts[2] == "kms"
	parts[3] != region
}

violation contains make_diag_full("pf-secretsmanager-kms-key", "ERROR", name,
	"Properties.KmsKeyId",
	sprintf("'%s' is the AWS managed key of another service; Secrets Manager may only use alias/aws/secretsmanager among AWS managed keys, and CreateSecret fails with \"Access to KMS is not allowed\"", [k]),
	_pf_smkk_fix, _pf_smkk_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	k := resolve(name, "Properties.KmsKeyId")
	is_string(k)
	alias := _pf_smkk_alias(k)
	startswith(alias, "alias/aws/")
	alias != "alias/aws/secretsmanager"
}

_pf_smkk_alias(k) := k if startswith(k, "alias/")

_pf_smkk_alias(k) := parts[5] if {
	parts := _pf_smkk_arn(k)
	startswith(parts[5], "alias/")
}
