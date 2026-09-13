package cdk_preflight

import rego.v1

# Measured against CreateMLTransform: 0.9 and 1.0 are refused, 2.0 and later are
# accepted. Kept as a set of strings so a new major version needs no edit.
_pf_gluemlver_eol := {"0.9", "1.0"}

violation contains make_diag_full("pf-glue-ml-transform-glue-version-eol", "ERROR", name,
	"Properties.GlueVersion",
	sprintf("Glue version %s is no longer supported for ML transforms; CreateMLTransform fails with \"Glue version %s is deprecated and is no longer supported for ML transforms. Specify Glue version 2.0 or higher.\"", [gv, gv]),
	"Use Glue version 2.0 or later",
	"https://docs.aws.amazon.com/glue/latest/dg/machine-learning.html") if {
	some name in resources_of_type("AWS::Glue::MLTransform")
	gv := _pf_gluelib_str(name, "Properties.GlueVersion")
	gv in _pf_gluemlver_eol
}
