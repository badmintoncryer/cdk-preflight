package cdk_preflight

import rego.v1

_pf_schemaobjectasargument_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

violation contains make_diag_full("pf-appsync-schema-object-as-argument", "ERROR", name,
	"Properties.Definition",
	sprintf("argument type '%s' is declared with `type`; the schema create fails with \"is not an input type\"", [t]),
	"Declare the argument shape with `input` instead of `type`",
	"https://docs.aws.amazon.com/appsync/latest/devguide/designing-your-schema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s := _pf_schemaobjectasargument_clean(sdl)
	objs := {m[1] | some m in regex.find_all_string_submatch_n(`type\s+([A-Za-z_][A-Za-z0-9_]*)`, s, -1)}
	some g in regex.find_all_string_submatch_n(`\(([^)]*)\)`, s, -1)
	some m in regex.find_all_string_submatch_n(`:\s*\[?\s*([A-Za-z_][A-Za-z0-9_]*)`, g[1], -1)
	t := m[1]
	t in objs
}
