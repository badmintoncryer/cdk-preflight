package cdk_preflight

import rego.v1

_pf_waflfc_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_Condition.html"

_pf_waflfc_fix := "Put one condition type per Conditions[] entry (use two entries for an action and a label)"

violation contains make_diag_full("pf-wafv2-logging-filter-condition", "ERROR", name,
	sprintf("Properties.LoggingFilter.Filters[%d].Conditions[%d]", [a, b]),
	sprintf("condition has %d keys; PutLoggingConfiguration fails with \"EXACTLY_ONE_CONDITION_REQUIRED\"", [count(object.keys(c))]),
	_pf_waflfc_fix, _pf_waflfc_url) if {
	some name in resources_of_type("AWS::WAFv2::LoggingConfiguration")
	filters := input.resources[name].properties.LoggingFilter.Filters
	some a
	conds := filters[a].Conditions

	# 1 つの body に裸の `some` を 2 つ書くとエンジンが局所変数を重複定義し、
	# Filters が 2 件以上のときカスタムパッケージ全体が落ちる（issue #150）。
	# 2 つ目はキー付き反復で書く。`some .. in` はスカラーだと評価エラーなので
	# is_array で守る。
	is_array(conds)
	some b, c in conds
	is_object(c)
	count(object.keys(c)) != 1
}
