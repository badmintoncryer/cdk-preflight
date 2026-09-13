package cdk_preflight

import rego.v1

_pf_schemaroottypemissing_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

_pf_schemaroottypemissing_defined(s) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?:type|input|interface|enum|union|scalar)\s+([A-Za-z_][A-Za-z0-9_]*)`, s, -1)
}

violation contains make_diag_full("pf-appsync-schema-root-type-missing", "ERROR", name,
	"Properties.Definition",
	sprintf("the schema block names '%s' as a root type but the SDL never declares it; the schema create fails with \"The operation type '%s' is not defined\"", [t, t]),
	"Declare the type the schema block names, or drop the operation from the block",
	"https://docs.aws.amazon.com/appsync/latest/devguide/designing-your-schema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s := _pf_schemaroottypemissing_clean(sdl)
	defined := _pf_schemaroottypemissing_defined(s)
	some b in regex.find_all_string_submatch_n(`schema\s*\{([^}]*)\}`, s, -1)
	some m in regex.find_all_string_submatch_n(`(?:query|mutation|subscription)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)`, b[1], -1)
	t := m[1]
	not t in defined
}
