package cdk_preflight

import rego.v1

# The engine's schema already requires PrimaryKeyColumnName inside
# FindMatchesParameters, so only the block being absent altogether is judged here.
_pf_gluemlfm_params(name) := p if {
	p := _pf_gluelib_get(name, "TransformParameters")
	is_object(p)
	object.get(p, "TransformType", "") == "FIND_MATCHES"
}

violation contains make_diag_full("pf-glue-ml-transform-find-matches-parameters", "ERROR", name,
	"Properties.TransformParameters.FindMatchesParameters",
	"The FIND_MATCHES transform has no FindMatchesParameters; CreateMLTransform fails with \"Find Matches parameters have not been set\"",
	"Add TransformParameters.FindMatchesParameters with PrimaryKeyColumnName",
	"https://docs.aws.amazon.com/glue/latest/dg/machine-learning.html") if {
	some name in resources_of_type("AWS::Glue::MLTransform")
	p := _pf_gluemlfm_params(name)
	not is_object(object.get(p, "FindMatchesParameters", null))
}

