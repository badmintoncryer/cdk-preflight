package cdk_preflight

import rego.v1

_pf_schemaduplicatefield_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

violation contains make_diag_full("pf-appsync-schema-duplicate-field", "ERROR", name,
	"Properties.Definition",
	sprintf("field '%s' is declared twice in the same type; the schema create fails with \"has declared a field more than once\"", [f]),
	"Give each field in a type a distinct name",
	"https://docs.aws.amazon.com/appsync/latest/devguide/designing-your-schema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s := regex.replace(_pf_schemaduplicatefield_clean(sdl), `\([^)]*\)`, " ")
	some b in regex.find_all_string_submatch_n(`(?:type|input|interface)\s+[A-Za-z_][A-Za-z0-9_]*[^{]*\{([^}]*)\}`, s, -1)
	fs := regex.find_all_string_submatch_n(`([A-Za-z_][A-Za-z0-9_]*)\s*:`, b[1], -1)
	some i, m in fs
	some j, n in fs
	j > i
	n[1] == m[1]
	f := m[1]
}
