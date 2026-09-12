package cdk_preflight

import rego.v1

# Only judgeable when the launch template is declared in the same template;
# an external id says nothing about its contents.
violation contains make_diag_full("pf-batch-ce-launch-template-userdata-type", "ERROR", name,
	"Properties.ComputeResources.LaunchTemplate.UserdataType",
	sprintf("UserdataType %v is set, but launch template %v has no ImageId (\"The userdataType attribute is only allowed when the launch template has an imageId.\")", [u, lid]),
	"Set ImageId in the launch template data, or drop UserdataType",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LaunchTemplateSpecification.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	lt := _pf_batch_lt(name)
	u := _pf_batch_oget(lt, "UserdataType")
	lid := _pf_batch_ref(_pf_batch_oget(lt, "LaunchTemplateId"))
	d := _pf_batch_oget(_pf_batch_props(lid), "LaunchTemplateData")
	not _pf_batch_ohas(d, "ImageId")
}
