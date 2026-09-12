package cdk_preflight

import rego.v1

_pf_schemaundefinedtypereference_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

_pf_schemaundefinedtypereference_defined(s) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?:type|input|interface|enum|union|scalar)\s+([A-Za-z_][A-Za-z0-9_]*)`, s, -1)
}

_pf_schemaundefinedtypereference_builtin := {"String", "Int", "Float", "Boolean", "ID"}

violation contains make_diag_full("pf-appsync-schema-undefined-type-reference", "ERROR", name,
	"Properties.Definition",
	sprintf("field type '%s' is never declared in the SDL; the schema create fails with \"The field type '%s' is not present when required\"", [t, t]),
	"Declare the type, or use one that the schema defines",
	"https://docs.aws.amazon.com/appsync/latest/devguide/designing-your-schema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s0 := _pf_schemaundefinedtypereference_clean(sdl)
	s1 := regex.replace(s0, `schema\s*\{[^}]*\}`, " ")
	s := regex.replace(s1, `\([^)]*\)`, " ")
	defined := _pf_schemaundefinedtypereference_defined(s0)
	some m in regex.find_all_string_submatch_n(`:\s*\[?\s*([A-Za-z_][A-Za-z0-9_]*)`, s, -1)
	t := m[1]
	not t in _pf_schemaundefinedtypereference_builtin
	not startswith(t, "AWS")
	not t in defined
}
