package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-ec2-config-image-type-eol", "ERROR", name,
	"Properties.ComputeResources.Ec2Configuration",
	sprintf("ImageType %v is an Amazon Linux 2 image (\"Amazon Linux 2 is end-of-life.\"); EKS support ended 2025-11-26 and ECS environment creation 2026-06-30", [it]),
	"Move to the matching AL2023 image type",
	"https://docs.aws.amazon.com/batch/latest/userguide/compute_resource_AMIs.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	some c in _pf_batch_ec2cfgs(name)
	it := _pf_batch_oget(c.value, "ImageType")
	_pf_batch_lit(it)
	it in _pf_batch_image_eol
}
