package cdk_preflight

import rego.v1

# The pass fixture sits on the lower limit only: an environment that reaches
# VALID with DesiredvCpus at the ceiling would launch real instances.
violation contains make_diag_full("pf-batch-ce-desired-vcpus-range", "ERROR", name,
	"Properties.ComputeResources.DesiredvCpus",
	sprintf("DesiredvCpus %v is outside MinvCpus %v .. MaxvCpus %v (\"desiredvCpus should be between minvCpus and maxvCpus.\")", [d, mn, mx]),
	"Keep MinvCpus <= DesiredvCpus <= MaxvCpus",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	d := _pf_batch_crget(name, "DesiredvCpus")
	is_number(d)
	mn := _pf_batch_crnum(name, "MinvCpus", 0)
	mx := _pf_batch_crget(name, "MaxvCpus")
	is_number(mx)
	_pf_batch_outside(d, mn, mx)
}
