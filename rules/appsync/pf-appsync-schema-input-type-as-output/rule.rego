package cdk_preflight

import rego.v1

_pf_schemainputtypeasoutput_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

violation contains make_diag_full("pf-appsync-schema-input-type-as-output", "ERROR", name,
	"Properties.Definition",
	sprintf("field type '%s' is declared with `input`; the schema create fails with \"is not an output type\"", [t]),
	"Declare a separate `type` for the output shape",
	"https://docs.aws.amazon.com/appsync/latest/devguide/designing-your-schema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s0 := _pf_schemainputtypeasoutput_clean(sdl)
	s := regex.replace(regex.replace(s0, `schema\s*\{[^}]*\}`, " "), `\([^)]*\)`, " ")
	inputs := {m[1] | some m in regex.find_all_string_submatch_n(`input\s+([A-Za-z_][A-Za-z0-9_]*)`, s0, -1)}
	some b in regex.find_all_string_submatch_n(`(?:type|interface)\s+[A-Za-z_][A-Za-z0-9_]*[^{]*\{([^}]*)\}`, s, -1)
	some m in regex.find_all_string_submatch_n(`:\s*\[?\s*([A-Za-z_][A-Za-z0-9_]*)`, b[1], -1)
	t := m[1]
	t in inputs
}
