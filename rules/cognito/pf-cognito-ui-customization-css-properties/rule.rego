package cdk_preflight

import rego.v1

# The CSS is an opaque string to every schema layer; the service only accepts
# its own customizable class names as selectors.

violation contains make_diag_full("pf-cognito-ui-customization-css-properties", "ERROR", name,
	"Properties.CSS",
	sprintf("CSS selector '%s' is not a Cognito customizable class; the UI customization call fails with \"The CSS class %s is not in the list of allowed classes.\"", [sel, sel]),
	"Style the Cognito classes (.banner-customizable, .submitButton-customizable, ...)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpooluicustomizationattachment.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolUICustomizationAttachment")
	css := resolve(name, "Properties.CSS")
	is_string(css)
	some chunk in split(css, "}")
	parts := split(chunk, "{")
	count(parts) > 1
	sel := trim_space(parts[0])
	sel != ""
	not contains(sel, "-customizable")
}
