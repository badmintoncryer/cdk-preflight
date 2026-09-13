package cdk_preflight

import rego.v1

# The per-zone minimum has the same exclusive ceiling as the fleet-wide one,
# but its own exception type and message.
violation contains make_diag_full("pf-codedeploy-config-zonal-minimum-healthy-per-zone-range", "ERROR", name,
	"Properties.ZonalConfig.MinimumHealthyHostsPerZone.Value",
	sprintf("MinimumHealthyHostsPerZone is FLEET_PERCENT %v; the deployment configuration create fails with \"The value of the 'Minimum health hosts per zone' setting when configured with a 'Type' value of 'FLEET_PERCENT' must be positive and less than 100.\"", [v]),
	"Use a FLEET_PERCENT value of 99 or less, or switch MinimumHealthyHostsPerZone.Type to HOST_COUNT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentconfig-zonalconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	resolve(name, "Properties.ZonalConfig.MinimumHealthyHostsPerZone.Type") == "FLEET_PERCENT"
	v := _pf_codedeploylib_num(resolve(name, "Properties.ZonalConfig.MinimumHealthyHostsPerZone.Value"))
	v > 99
}
