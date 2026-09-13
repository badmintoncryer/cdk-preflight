package cdk_preflight

import rego.v1

# The bundled registry schema types MaxConcurrentRuns as a bare integer.
violation contains make_diag_full("pf-glue-workflow-max-concurrent-runs-min", "ERROR", name,
	"Properties.MaxConcurrentRuns",
	sprintf("MaxConcurrentRuns is %v; CreateWorkflow fails with \"MaxConcurrentRuns should be greater than or equal to 1 if present.\"", [n]),
	"Set MaxConcurrentRuns to 1 or more, or leave it out",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateWorkflow.html") if {
	some name in resources_of_type("AWS::Glue::Workflow")
	n := _pf_gluelib_num(name, "Properties.MaxConcurrentRuns")
	n < 1
}
