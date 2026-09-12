package cdk_preflight

import rego.v1

_pf_schemaduplicatetype_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

violation contains make_diag_full("pf-appsync-schema-duplicate-type", "ERROR", name,
	"Properties.Definition",
	sprintf("type '%s' is declared more than once; the schema create fails to parse the SDL", [t]),
	"Declare each type once, or use `extend type` for the second block",
	"https://docs.aws.amazon.com/appsync/latest/devguide/designing-your-schema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s := _pf_schemaduplicatetype_clean(sdl)
	ms := regex.find_all_string_submatch_n(`(?:type|input|interface|enum|union|scalar)\s+([A-Za-z_][A-Za-z0-9_]*)`, s, -1)
	some i, m in ms
	some j, n in ms
	j > i
	n[1] == m[1]
	t := m[1]
}
