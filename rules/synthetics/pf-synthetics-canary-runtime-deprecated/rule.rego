package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-runtime-deprecated", "ERROR", name,
	"Properties.RuntimeVersion",
	sprintf("RuntimeVersion '%s' is a deprecated Synthetics runtime (list read 2026-09-24); existing canaries keep running on it but \"You can't create canaries using deprecated runtime versions\"", [rt]),
	"Move to a supported runtime (syn-nodejs-puppeteer-17.0, syn-nodejs-playwright-8.0, syn-python-selenium-12.0 as of 2026-09-24)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Runtime_Support_Policy.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	rt := _pf_synlib_str(name, ["RuntimeVersion"])
	rt in _pf_synlib_deprecated_runtimes
}
