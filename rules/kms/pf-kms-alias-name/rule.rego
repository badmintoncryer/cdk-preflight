package cdk_preflight

import rego.v1

_pf_kmsal_url := "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html"

_pf_kmsal_fix := "Use alias/<name> with letters, digits, /, _ and - only, and a prefix other than alias/aws/"

violation contains make_diag_full("pf-kms-alias-name", "ERROR", name,
	"Properties.AliasName",
	sprintf("'%s' uses the reserved alias/aws/ prefix; CreateAlias fails with \"The alias name for a customer managed CMK cannot begin with alias/aws/.\" (the CloudFormation handler only reports \"Error occurred during operation 'CreateAlias'.\")", [a]),
	_pf_kmsal_fix, _pf_kmsal_url) if {
	some name in resources_of_type("AWS::KMS::Alias")
	a := resolve(name, "Properties.AliasName")
	is_string(a)
	startswith(lower(a), "alias/aws/")
}

violation contains make_diag_full("pf-kms-alias-name", "ERROR", name,
	"Properties.AliasName",
	sprintf("'%s' contains a colon; CreateAlias fails with \"contains invalid characters for an alias\" (allowed: letters, digits, /, _ and -)", [a]),
	_pf_kmsal_fix, _pf_kmsal_url) if {
	some name in resources_of_type("AWS::KMS::Alias")
	a := resolve(name, "Properties.AliasName")
	is_string(a)
	contains(a, ":")
}
