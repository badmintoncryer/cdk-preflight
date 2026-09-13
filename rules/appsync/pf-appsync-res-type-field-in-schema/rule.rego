package cdk_preflight

import rego.v1

# Judged only when an inline schema for the same API is a sibling resource.
_pf_restypefieldinschema_sdl(api) := s if {
	some g in resources_of_type("AWS::AppSync::GraphQLSchema")
	resolve(g, "Properties.ApiId") == api
	s := resolve(g, "Properties.Definition")
	is_string(s)
}

violation contains make_diag_full("pf-appsync-res-type-field-in-schema", "ERROR", name,
	"Properties.TypeName",
	sprintf("the resolver attaches to type '%s', which the schema in this template does not declare; the resolver create fails because there is no such type", [t]),
	"Attach the resolver to a type the schema declares",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	api := resolve(name, "Properties.ApiId")
	sdl := _pf_restypefieldinschema_sdl(api)
	t := resolve(name, "Properties.TypeName")
	is_string(t)
	count(regex.find_n(sprintf(`type\s+%s\b`, [t]), sdl, -1)) == 0
}
