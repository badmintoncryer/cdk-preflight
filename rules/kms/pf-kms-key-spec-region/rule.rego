package cdk_preflight

import rego.v1

_pf_kmsreg_url := "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html"

_pf_kmsreg_fix := "Use an RSA or ECC key spec outside cn-* regions"

# Region comparison needs the deploy region (data.cdk_preflight.deploy_region, enforce mode only).
violation contains make_diag_full("pf-kms-key-spec-region", "ERROR", name,
	"Properties.KeySpec",
	sprintf("KeySpec SM2 is only available in China regions, and this stack deploys to %s; CreateKey fails with \"KeySpec SM2 is not supported in this Region\"", [region]),
	_pf_kmsreg_fix, _pf_kmsreg_url) if {
	region := data.cdk_preflight.deploy_region
	not startswith(region, "cn-")
	some name in resources_of_type("AWS::KMS::Key")
	resolve(name, "Properties.KeySpec") == "SM2"
}
