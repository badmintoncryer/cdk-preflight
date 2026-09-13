package cdk_preflight

import rego.v1

# The floor is per worker type in the service message but 2 everywhere it
# was measured (G.1X, G.2X, G.025X); the bundled schema has no minimum.
violation contains make_diag_full("pf-glue-job-number-of-workers-min", "ERROR", name,
	"Properties.NumberOfWorkers",
	sprintf("NumberOfWorkers %v; a job needs at least 2 workers", [nw]),
	"Set NumberOfWorkers to 2 or more",
	"https://docs.aws.amazon.com/glue/latest/dg/add-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	nw := _pf_gluelib_num(name, "Properties.NumberOfWorkers")
	nw < 2
}
