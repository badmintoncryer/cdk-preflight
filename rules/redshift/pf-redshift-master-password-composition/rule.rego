package cdk_preflight

import rego.v1

_pf_rspwc_url := "https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html"

_pf_rspwc_fix := "Include at least one uppercase letter, one lowercase letter and one digit, or use ManageMasterPassword"

_pf_rspwc_pw(name) := pw if {
	pw := _pf_redshiftlib_str(name, "MasterUserPassword")
}

violation contains make_diag_full("pf-redshift-master-password-composition", "ERROR", name,
	"Properties.MasterUserPassword",
	"MasterUserPassword has no uppercase letter; CreateCluster rejects it (\"The parameter MasterUserPassword must contain at least 1 upper case letter.\")",
	_pf_rspwc_fix, _pf_rspwc_url) if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	pw := _pf_rspwc_pw(name)
	not regex.match(`[A-Z]`, pw)
}

violation contains make_diag_full("pf-redshift-master-password-composition", "ERROR", name,
	"Properties.MasterUserPassword",
	"MasterUserPassword has no lowercase letter; CreateCluster rejects it (the API requires at least one lowercase letter)",
	_pf_rspwc_fix, _pf_rspwc_url) if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	pw := _pf_rspwc_pw(name)
	not regex.match(`[a-z]`, pw)
}

violation contains make_diag_full("pf-redshift-master-password-composition", "ERROR", name,
	"Properties.MasterUserPassword",
	"MasterUserPassword has no digit; CreateCluster rejects it (the API requires at least one number)",
	_pf_rspwc_fix, _pf_rspwc_url) if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	pw := _pf_rspwc_pw(name)
	not regex.match(`[0-9]`, pw)
}
