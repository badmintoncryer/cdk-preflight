package cdk_preflight

import rego.v1

_pf_kmsat_url := "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html"

_pf_kmsat_fix := "Point TargetKeyId at a key id or ARN (Ref / Fn::GetAtt Key.Arn of a key in this stack) in the deploy account and region"

# [partition, service, region, account, resource...] of a literal ARN; undefined otherwise
_pf_kmsat_arn(s) := parts if {
	is_string(s)
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) >= 6
}

violation contains make_diag_full("pf-kms-alias-target", "ERROR", name,
	"Properties.TargetKeyId",
	sprintf("'%s' is an alias, not a key; CreateAlias fails with \"Aliases must refer to keys. Not aliases\"", [t]),
	_pf_kmsat_fix, _pf_kmsat_url) if {
	some name in resources_of_type("AWS::KMS::Alias")
	t := resolve(name, "Properties.TargetKeyId")
	is_string(t)
	_pf_kmsat_is_alias(t)
}

_pf_kmsat_is_alias(t) if startswith(t, "alias/")

_pf_kmsat_is_alias(t) if contains(t, ":alias/")

# Region / account comparison needs the deploy environment (enforce mode only).
violation contains make_diag_full("pf-kms-alias-target", "ERROR", name,
	"Properties.TargetKeyId",
	sprintf("key ARN is in region '%s' but the alias deploys to '%s'; CreateAlias fails with \"Invalid arn %s\"", [parts[3], region, parts[3]]),
	_pf_kmsat_fix, _pf_kmsat_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::KMS::Alias")
	parts := _pf_kmsat_arn(resolve(name, "Properties.TargetKeyId"))
	parts[2] == "kms"
	parts[3] != region
}

violation contains make_diag_full("pf-kms-alias-target", "ERROR", name,
	"Properties.TargetKeyId",
	sprintf("key ARN belongs to account %s but the alias deploys to account %s; CreateAlias fails with \"This operation cannot be called cross account\"", [parts[4], account]),
	_pf_kmsat_fix, _pf_kmsat_url) if {
	account := data.cdk_preflight.deploy_account
	some name in resources_of_type("AWS::KMS::Alias")
	parts := _pf_kmsat_arn(resolve(name, "Properties.TargetKeyId"))
	parts[2] == "kms"
	parts[4] != account
}
