package cdk_preflight

import rego.v1

# Mounting EFS requires the function to run inside a VPC. Key presence is
# checked against the preprocessed document (see AGENTS.md).
_pf_lefsv_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

violation contains make_diag_full("pf-lambda-efs-requires-vpc", "ERROR", name,
	"Properties.VpcConfig",
	"FileSystemConfigs without VpcConfig; the function create fails with \"Function must be configured to execute in a VPC to reference access point ... Please update the function configuration to include VPC subnets and security groups.\"",
	"Add VpcConfig with subnets that have EFS mount targets in their AZs",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-function.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	props := _pf_lefsv_props(name)
	object.get(props, "FileSystemConfigs", "__pf_absent") != "__pf_absent"
	object.get(props, "VpcConfig", "__pf_absent") == "__pf_absent"
}
