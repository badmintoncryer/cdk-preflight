package cdk_preflight

import rego.v1

_pf_schemarequiresqueryroot_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

violation contains make_diag_full("pf-appsync-schema-requires-query-root", "ERROR", name,
	"Properties.Definition",
	"the SDL declares no Query type and no schema{} block naming one; the schema create fails with \"There is no top level schema object\"",
	"Add `type Query { ... }`, or a schema{} block whose query: names an existing type",
	"https://docs.aws.amazon.com/appsync/latest/devguide/designing-your-schema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s := _pf_schemarequiresqueryroot_clean(sdl)
	count(regex.find_n(`type\s+Query\b`, s, -1)) == 0
	count(regex.find_n(`schema\s*\{[^}]*\bquery\s*:`, s, -1)) == 0
}
