package cdk_preflight

import rego.v1

_pf_ssmdn_url := "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CreateDocument.html"

_pf_ssmdn_fix := "Choose a document name that does not start with aws-, amazon or amzn"

violation contains make_diag_full("pf-ssm-document-name", "ERROR", name,
	"Properties.Name",
	sprintf("'%s' starts with the reserved prefix '%s'; CreateDocument fails with \"Invalid document name %s\"", [n, pfx, n]),
	_pf_ssmdn_fix, _pf_ssmdn_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	n := resolve(name, "Properties.Name")
	is_string(n)
	some pfx in ["aws-", "amazon", "amzn"]
	startswith(lower(n), pfx)
}
