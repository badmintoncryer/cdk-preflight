package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-cr-total-quantity-negative", "ERROR", name,
	"Properties.TotalQuantity",
	sprintf("TotalQuantity is %v (\"totalQuantity cannot be a negative number.\")", [n]),
	"Set TotalQuantity to 0 or more",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateConsumableResource.html") if {
	some name in resources_of_type("AWS::Batch::ConsumableResource")
	n := to_number(resolve(name, "Properties.TotalQuantity"))
	n < 0
}
