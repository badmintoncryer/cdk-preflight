package cdk_preflight

import rego.v1

# Not a schema enum: these values were valid until the support policy
# retired them (0.9/1.0/2.0 on 2026-04-01). The set grows over time, so it
# lists what CreateJob rejects today rather than what it accepts.
_pf_gluejobeol_versions := {"0.9", "1.0", "2.0"}

violation contains make_diag_full("pf-glue-job-glue-version-eol", "ERROR", name,
	"Properties.GlueVersion",
	sprintf("GlueVersion %v reached end of life; CreateJob no longer accepts it", [gv]),
	"Move the job to GlueVersion 3.0 or later",
	"https://docs.aws.amazon.com/glue/latest/dg/glue-version-support-policy.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	gv := _pf_gluelib_glue_version(name)
	gv in _pf_gluejobeol_versions
}
