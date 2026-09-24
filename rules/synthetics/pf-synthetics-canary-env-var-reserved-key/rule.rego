package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-env-var-reserved-key", "ERROR", name,
	sprintf("Properties.RunConfig.EnvironmentVariables.%s", [k]),
	sprintf("RunConfig.EnvironmentVariables sets '%s', which is one of Lambda's reserved environment variables; a canary run is a Lambda function, so the name is not yours to set", [k]),
	"Rename the variable (the runtime already exposes the reserved ones)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-runconfig.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	some k in object.keys(_pf_synlib_env(name))
	k in _pf_synlib_reserved_env
}
