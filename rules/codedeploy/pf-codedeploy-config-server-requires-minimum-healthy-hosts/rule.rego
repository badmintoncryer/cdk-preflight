package cdk_preflight

import rego.v1

# MinimumHealthyHosts is what a Server deployment configuration configures; the
# service has no default for it. An absent ComputePlatform is Server, so the same
# rejection applies to a configuration that never names a platform.
violation contains make_diag_full("pf-codedeploy-config-server-requires-minimum-healthy-hosts", "ERROR", name,
	"Properties.MinimumHealthyHosts",
	"A Server deployment configuration has no MinimumHealthyHosts; the create fails with \"minimum healthy hosts argument is missing\"",
	"Add MinimumHealthyHosts with a Type (HOST_COUNT or FLEET_PERCENT) and a Value",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codedeploy-deploymentconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	_pf_codedeploylib_platform(name) == "Server"
	not _pf_codedeploylib_has(_pf_codedeploylib_props(name), "MinimumHealthyHosts")
}
