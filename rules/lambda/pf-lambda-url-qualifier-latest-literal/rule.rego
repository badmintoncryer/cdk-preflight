package cdk_preflight

import rego.v1

_pf_luql_fix := "Omit Qualifier to attach the URL to $LATEST"

_pf_luql_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-url.html"

violation contains make_diag_full("pf-lambda-url-qualifier-latest-literal", "ERROR", name,
	"Properties.Qualifier",
	"Qualifier $LATEST; the unpublished version is addressed by leaving Qualifier out and the property pattern does not accept the literal",
	_pf_luql_fix, _pf_luql_url) if {
	some name in _pf_lam_url
	resolve(name, "Properties.Qualifier") == "$LATEST"
}
