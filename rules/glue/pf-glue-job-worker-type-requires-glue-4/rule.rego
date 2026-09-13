package cdk_preflight

import rego.v1

# G.12X/G.16X and the whole R family arrived with Glue 4.0. The older set is
# spelled out rather than compared numerically so that a future 5.x version
# never has to be added here; 0.9-2.0 are already end of life
# (pf-glue-job-glue-version-eol) but stay listed for a precise message.
_pf_gluejob4_types := {"G.12X", "G.16X", "R.1X", "R.2X", "R.4X", "R.8X"}

_pf_gluejob4_older := {"0.9", "1.0", "2.0", "3.0"}

violation contains make_diag_full("pf-glue-job-worker-type-requires-glue-4", "ERROR", name,
	"Properties.WorkerType",
	sprintf("WorkerType %v with GlueVersion %v; this worker type needs Glue 4.0 or later", [wt, gv]),
	"Set GlueVersion to 4.0 or later, or pick a worker type the version supports",
	"https://docs.aws.amazon.com/glue/latest/dg/worker-types.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	wt := _pf_gluelib_worker_type(name)
	wt in _pf_gluejob4_types
	gv := _pf_gluelib_glue_version(name)
	gv in _pf_gluejob4_older
}
