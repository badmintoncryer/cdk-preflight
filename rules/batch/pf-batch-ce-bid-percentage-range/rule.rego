package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-bid-percentage-range", "ERROR", name,
	"Properties.ComputeResources.BidPercentage",
	sprintf("BidPercentage is %v (\"Bid percentage must be between 0 to 100.\")", [b]),
	"Use a percentage of the On-Demand price between 0 and 100",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	b := _pf_batch_crget(name, "BidPercentage")
	is_number(b)
	_pf_batch_outside(b, 0, 100)
}
