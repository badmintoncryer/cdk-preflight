package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-env-vars-max-4kb", "ERROR", name,
	"Properties.RunConfig.EnvironmentVariables",
	sprintf("RunConfig.EnvironmentVariables encodes to %v bytes of JSON; the total size of a canary's environment variables cannot exceed 4 KB, and no single property carries the sum", [s]),
	"Move the bulk out of the environment (an S3 object or a Secrets Manager secret the script reads)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-runconfig.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	s := count(json.marshal(_pf_synlib_env(name)))
	s > 4096
}
