package cdk_preflight

import rego.v1

_pf_ldkr_fix := "Build the key ARN with ${AWS::Region}"

_pf_ldkr_url := "https://docs.aws.amazon.com/lambda/latest/dg/encrypt-zip-package.html"

violation contains make_diag_full("pf-lambda-durable-kms-key-region", "ERROR", name,
	"Properties.DurableConfig.KMSKeyArn",
	sprintf("KMS key region '%v' is not the deploy region '%v'; durable state is encrypted with a key in the function's own region", [parts[3], region]),
	_pf_ldkr_fix, _pf_ldkr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in _pf_lam_fn
	dc := _pf_lam_obj(_pf_lam_props(name), "DurableConfig")
	parts := _pf_lam_arn(object.get(dc, "KMSKeyArn", ""))
	parts[2] == "kms"
	parts[3] != region
}
