package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-active-tracing-runtime", "ERROR", name,
	"Properties.RunConfig.ActiveTracing",
	sprintf("RunConfig.ActiveTracing is on but the canary runs '%s'; active X-Ray tracing is only offered on the Node.js (syn-nodejs-2.0 and later) and Java runtimes", [rt]),
	"Drop ActiveTracing, or move the canary to a Node.js runtime",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-runconfig.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	resolve(name, "Properties.RunConfig.ActiveTracing") == true
	rt := _pf_synlib_str(name, ["RuntimeVersion"])
	startswith(rt, "syn-python-selenium-")
}
