package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-timeout-within-schedule", "ERROR", name,
	"Properties.RunConfig.TimeoutInSeconds",
	sprintf("RunConfig.TimeoutInSeconds is %v but Schedule.Expression '%s' starts a run every %v seconds; a canary cannot be allowed to run longer than the gap between its runs", [t, expr, mins * 60]),
	"Lower TimeoutInSeconds to the run frequency or below, or schedule the canary less often — omitting TimeoutInSeconds uses the frequency itself",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-runconfig.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	t := to_number(resolve(name, "Properties.RunConfig.TimeoutInSeconds"))
	expr := resolve(name, "Properties.Schedule.Expression")
	r := _pf_synlib_rate(expr)
	mins := _pf_synlib_rate_minutes(r[0], r[1])
	mins > 0
	t > mins * 60
}
