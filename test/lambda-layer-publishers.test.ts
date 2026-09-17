/**
 * pf-lambda-layer-cross-account-needs-permission exempts the accounts AWS
 * publishes layers from. That table is generated from aws-cdk-lib region-info,
 * which grows as AWS adds regions and layer families; this test turns red when
 * the installed aws-cdk-lib knows a publisher the rule does not, so a CDK bump
 * regenerates the table instead of reintroducing the false positive of #238.
 */
import * as fs from 'fs';
import * as path from 'path';
import { Fact } from 'aws-cdk-lib/region-info';

const RULE = path.join(__dirname, '..', 'rules', 'lambda', 'pf-lambda-layer-cross-account-needs-permission', 'rule.rego');

/** Every account that owns a Lambda layer ARN recorded in region-info. */
function regionInfoPublishers(): string[] {
  const out = new Set<string>();
  for (const region of Fact.regions) {
    for (const name of Fact.names) {
      const value = Fact.find(region, name);
      const m = typeof value === 'string' ? /^arn:aws[a-z-]*:lambda:[a-z0-9-]+:(\d{12}):layer:/.exec(value) : null;
      if (m) out.add(m[1]);
    }
  }
  return [...out].sort();
}

/** The accounts listed in the rule's _pf_llcp_aws_publishers set. */
function ruleTable(): Set<string> {
  const rego = fs.readFileSync(RULE, 'utf8');
  const block = /_pf_llcp_aws_publishers := \{([^}]*)\}/.exec(rego);
  if (!block) throw new Error('_pf_llcp_aws_publishers not found in rule.rego');
  return new Set([...block[1].matchAll(/"(\d{12})"/g)].map((m) => m[1]));
}

test('the AWS layer-publisher table carries every account aws-cdk-lib region-info knows', () => {
  const table = ruleTable();
  const missing = regionInfoPublishers().filter((a) => !table.has(a));
  expect(missing).toEqual([]);
});
