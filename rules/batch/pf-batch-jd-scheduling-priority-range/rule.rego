package cdk_preflight

import rego.v1

# Both ends measured 2026-09-10 via RegisterJobDefinition: 100000 and -1 give
# the same message, so one rule covers the range.
violation contains make_diag_full("pf-batch-jd-scheduling-priority-range", "ERROR", name,
	"Properties.SchedulingPriority",
	sprintf("SchedulingPriority %v is out of range (\"Scheduling priority must be between 0 and 9999.\")", [n]),
	"Use a priority between 0 and 9999",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := to_number(resolve(name, "Properties.SchedulingPriority"))
	_pf_batch_outside(n, 0, 9999)
}
