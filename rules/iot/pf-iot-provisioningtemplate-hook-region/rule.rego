package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-provisioningtemplate-hook-region", "ERROR", name,
	"Properties.PreProvisioningHook.TargetArn",
	sprintf("the pre-provisioning hook is in '%s' but the template deploys to '%s'; CreateProvisioningTemplate rejects the cross-region ARN with \"Invalid arguments in the call\" (it never names the region - a same-region ARN gets as far as \"Access denied during lambda validation\")", [fnRegion, region]),
	"Point PreProvisioningHook.TargetArn at a function in the template's own region",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_ProvisioningHook.html") if {
	some name in resources_of_type("AWS::IoT::ProvisioningTemplate")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	fnRegion := _pf_iotlib_arn_region(resolve(name, "Properties.PreProvisioningHook.TargetArn"), "lambda")
	fnRegion != region
}
