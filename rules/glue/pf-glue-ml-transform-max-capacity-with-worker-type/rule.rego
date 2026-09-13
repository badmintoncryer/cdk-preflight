package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-glue-ml-transform-max-capacity-with-worker-type", "ERROR", name,
	"Properties.MaxCapacity",
	sprintf("MaxCapacity is set together with %s; CreateMLTransform fails with \"Cannot set Max Capacity and Worker Num/Type at the same time\"", [k]),
	"Size the transform with MaxCapacity, or with WorkerType and NumberOfWorkers - not both",
	"https://docs.aws.amazon.com/glue/latest/dg/machine-learning.html") if {
	some name in resources_of_type("AWS::Glue::MLTransform")
	_pf_gluelib_has(name, "MaxCapacity")
	some k in ["WorkerType", "NumberOfWorkers"]
	_pf_gluelib_has(name, k)
}
