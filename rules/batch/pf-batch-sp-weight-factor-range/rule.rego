package cdk_preflight

import rego.v1

# The CFN schema says 0-1000, the service says 0.0001-999.9999: both edges
# walk straight through the bundled engine.
violation contains make_diag_full("pf-batch-sp-weight-factor-range", "ERROR", name,
	"Properties.FairsharePolicy.ShareDistribution",
	sprintf("share identifier %v has WeightFactor %v (\"Weight factor should be between 0.0001 and 999.9999.\")", [si, w]),
	"Set WeightFactor between 0.0001 and 999.9999",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ShareAttributes.html") if {
	some name in resources_of_type("AWS::Batch::SchedulingPolicy")
	some e in flatten_list(name, "Properties.FairsharePolicy.ShareDistribution")
	si := _pf_batch_oget(e.value, "ShareIdentifier")
	w := to_number(_pf_batch_oget(e.value, "WeightFactor"))
	_pf_batch_outside(w, 0.0001, 999.9999)
}
