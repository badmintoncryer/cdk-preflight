package cdk_preflight

import rego.v1

# ECS and EKS environments take disjoint image types, so one set lookup covers both.
violation contains make_diag_full("pf-batch-ce-ec2-config-image-type", "ERROR", name,
	"Properties.ComputeResources.Ec2Configuration",
	sprintf("ImageType %v is not one of %v (\"Invalid imageType in ComputeResources.ec2Configuration\")", [it, concat(", ", sort(allowed))]),
	"Use an ECS_* image type on an ECS environment and an EKS_* one on an EKS environment",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_Ec2Configuration.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	allowed := _pf_batch_image_types(name)
	some c in _pf_batch_ec2cfgs(name)
	it := _pf_batch_oget(c.value, "ImageType")
	_pf_batch_lit(it)
	not it in allowed
}
