package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-account-policy-transformer-document", "ERROR", name,
	"Properties.PolicyDocument",
	"The transformer policy document is not a JSON array of processors; PutAccountPolicy fails with \"Invalid json transformer config provided\"",
	"Wrap the processors in an array: [{\"parseJSON\": {}}, ...]",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAccountPolicy.html") if {
	some name in resources_of_type("AWS::Logs::AccountPolicy")
	resolve(name, "Properties.PolicyType") == "TRANSFORMER_POLICY"
	doc := resolve(name, "Properties.PolicyDocument")
	is_string(doc)
	json.is_valid(doc)
	not is_array(json.unmarshal(doc))
}
