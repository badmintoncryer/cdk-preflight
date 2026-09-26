package cdk_preflight

import rego.v1

_pf_aps_adq_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-aps-anomalydetector-randomcutforestconfiguration.html"

_pf_aps_adq_fix := "Wrap the whole expression in avg, count, group, max, min, quantile, stddev, stdvar or sum; topk, bottomk and count_values are not supported here"

# The query has to be one supported aggregation operator wrapping the whole
# expression. The operator list is the doc's, which is PromQL's minus topk,
# bottomk and count_values. The greedy `.*` is what makes this a wrapping test
# rather than a prefix test: a nested call (sum(rate(up[5m]))) matches, while a
# root operator whose closing parenthesis is not the last character (sum(up)+1)
# does not, and a prefix clause (sum by (job) (up)) never reaches the `(`.
violation contains make_diag_full("pf-aps-ad-query-aggregation-operator", "ERROR", name,
	"Properties.Configuration.RandomCutForest.Query",
	sprintf("Query \"%v\" is not wrapped by a supported aggregation operator; CreateAnomalyDetector fails with \"Unsupported PromQL expression for RandomCutForest, expression's root must be a supported aggregation operator\"", [q]),
	_pf_aps_adq_fix, _pf_aps_adq_url) if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	q := _pf_aps_str(name, "Properties.Configuration.RandomCutForest.Query")
	not regex.match(`^\s*(avg|count|group|max|min|quantile|stddev|stdvar|sum)\s*\(.*\)\s*$`, q)
}

# The postfix form (sum(up) by (job)) gets past the check above -- the greedy
# `.*` swallows `up) by (job` and the string does end in `)` -- and the service
# rejects it for the clause rather than for the operator. Anchored at the end so
# a by clause nested inside the root aggregation, which is ordinary PromQL and
# was never measured as rejected, stays silent.
violation contains make_diag_full("pf-aps-ad-query-aggregation-operator", "ERROR", name,
	"Properties.Configuration.RandomCutForest.Query",
	sprintf("Query \"%v\" ends in a by/without clause on the root aggregation; CreateAnomalyDetector fails with \"Unsupported PromQL expression for RandomCutForest, expression root's aggregation operator cannot include a by or without clause\"", [q]),
	_pf_aps_adq_fix, _pf_aps_adq_url) if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	q := _pf_aps_str(name, "Properties.Configuration.RandomCutForest.Query")
	regex.match(`\)\s*(by|without)\s*\([^()]*\)\s*$`, q)
}
