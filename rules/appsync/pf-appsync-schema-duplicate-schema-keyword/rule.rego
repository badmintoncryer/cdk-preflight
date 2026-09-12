package cdk_preflight

import rego.v1

_pf_schemaduplicateschemakeyword_clean(s) := c if {
	a := regex.replace(s, `"""[^"]*"""`, " ")
	b := regex.replace(a, `#[^\n]*`, " ")
	c := regex.replace(b, `@[A-Za-z_][A-Za-z0-9_]*\([^)]*\)`, " ")
}

violation contains make_diag_full("pf-appsync-schema-duplicate-schema-keyword", "ERROR", name,
	"Properties.Definition",
	sprintf("the SDL has %d schema{} blocks; the schema create fails to parse the SDL", [count(regex.find_n(`schema\s*\{`, s, -1))]),
	"Keep a single schema{} block",
	"https://docs.aws.amazon.com/appsync/latest/devguide/designing-your-schema.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLSchema")
	sdl := resolve(name, "Properties.Definition")
	is_string(sdl)
	s := _pf_schemaduplicateschemakeyword_clean(sdl)
	count(regex.find_n(`schema\s*\{`, s, -1)) > 1
}
