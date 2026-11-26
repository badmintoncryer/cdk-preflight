package cdk_preflight

import rego.v1

# EnableSso の前提は access URL（エイリアス）。CreateAlias を書かずに EnableSso: true にすると SSO の有効化が失敗する見込み。
# CreateAlias が Fn::If や Ref で決まらないときは黙る。
_pf_dssso_true(name, k) if resolve(name, sprintf("Properties.%s", [k])) == true

_pf_dssso_true(name, k) if resolve(name, sprintf("Properties.%s", [k])) == "true"

_pf_dssso_unknown(name, k) if {
	v := _pf_oval(input.resources[name].properties, k)
	is_object(v)
}

violation contains make_diag_full("pf-ds-msad-sso-requires-alias", "ERROR", name,
	"Properties.EnableSso",
	"EnableSso is true but CreateAlias is not; single sign-on needs the directory's access URL alias",
	"Set CreateAlias: true (and pick a globally unique directory alias via Name/ShortName) or drop EnableSso",
	"https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_single_sign_on.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	_pf_dssso_true(name, "EnableSso")
	not _pf_dssso_true(name, "CreateAlias")
	not _pf_dssso_unknown(name, "CreateAlias")
}
