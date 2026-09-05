package cdk_preflight

import rego.v1

_pf_ecrsign_url := "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutSigningConfiguration.html"

_pf_ecrsign_fix := "Create the AWS Signer profile in the registry region and reference that ARN"

violation contains make_diag_full("pf-ecr-signing-profile-region", "ERROR", name,
	sprintf("Properties.Rules[%d].SigningProfileArn", [i]),
	sprintf("the signing profile is in region '%s' but the registry is in '%s'; PutSigningConfiguration fails with \"The region of signing profile ARN ... is '%s' but must be '%s' (the current region)\"", [parts[3], region, parts[3], region]),
	_pf_ecrsign_fix, _pf_ecrsign_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::ECR::SigningConfiguration")
	rules := resolve(name, "Properties.Rules")
	is_array(rules)
	some i, rule in rules
	parts := _pf_ecrlib_arn(object.get(rule, "SigningProfileArn", null))
	parts[2] == "signer"
	parts[3] != region
}
