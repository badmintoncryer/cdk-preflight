package cdk_preflight

import rego.v1

# Zonal deployments roll through Availability Zones one at a time, which only
# the EC2/on-premises platform does.
violation contains make_diag_full("pf-codedeploy-config-zonal-server-only", "ERROR", name,
	"Properties.ZonalConfig",
	sprintf("ZonalConfig is set on a %v deployment configuration; the create fails with \"Zonal deployments are only supported with EC2 deployments.\"", [p]),
	"Drop ZonalConfig - it exists only for the Server (EC2/on-premises) platform",
	"https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations-create.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	p := _pf_codedeploylib_platform(name)
	p != "Server"
	_pf_codedeploylib_has(_pf_codedeploylib_props(name), "ZonalConfig")
}
