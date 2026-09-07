package cdk_preflight

import rego.v1

_pf_luqp_fix := "Include the same alias in the Permission FunctionName"

_pf_luqp_url := "https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html"

# Permission が同じ修飾子のエイリアスリソースを指しているなら満たしている。
_pf_luqp_alias(fn, q) if {
	fn in _pf_lam_alias
	resolve(fn, "Properties.Name") == q
}

violation contains make_diag_full("pf-lambda-url-qualifier-permission-match", "ERROR", name,
	"Properties.Qualifier",
	sprintf("URL on qualifier '%v' but a function URL permission names an unqualified function; the resource policy is attached to the unqualified function and never applies to the alias", [q]),
	_pf_luqp_fix, _pf_luqp_url) if {
	some name in _pf_lam_url
	q := resolve(name, "Properties.Qualifier")
	is_string(q)
	some p in _pf_lam_perm
	props := _pf_lam_props(p)
	_pf_lam_has_key(props, "FunctionUrlAuthType")
	fn := resolve(p, "Properties.FunctionName")
	is_string(fn)
	not endswith(fn, sprintf(":%v", [q]))
	not _pf_luqp_alias(fn, q)
}
