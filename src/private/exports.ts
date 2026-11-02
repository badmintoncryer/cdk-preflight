import * as fs from 'fs';
import type { IPolicyValidationContext, IPolicyValidationPlugin, PolicyValidationPluginReport, PolicyViolation } from 'aws-cdk-lib';
import { isConcreteAccount, isConcreteRegion } from './enforce';
import { stackNameOf } from './quota';

/**
 * スタックをまたぐ Export の検査（issue #263 の候補 1 と 2）。Rego はテンプレートを 1 枚ずつしか
 * 見ないので、アプリの全スタックを読むこのプラグイン側で判定する。
 *
 * - pf-cfn-export-name-conflict: 同じ環境（account × region）に向かう 2 つのスタックが同じ
 *   Export.Name を宣言している。後からデプロイする方が
 *   "Export with name X is already exported by stack Y" で失敗する。
 * - pf-cfn-import-value-missing-export: `Fn::ImportValue` の名前が、このアプリのスタックの命名
 *   （CDK が自動で付ける `<stackName>:...`）なのに、同じ環境のそのスタックが export していない。
 *   "No export named X found" で失敗する。アプリの外のスタックが同じ名前を export している
 *   可能性はテンプレートからは消せないので、名前がアプリ内のスタック名で始まるものに限る。
 *
 * どちらも実アカウントでの再現（bench）がまだ無いので、AGENTS.md の doc-only と同じく
 * warning として報告し、synth は止めない。
 */
export const EXPORT_CONFLICT_RULE = 'pf-cfn-export-name-conflict';
export const IMPORT_MISSING_RULE = 'pf-cfn-import-value-missing-export';
export const EXPORT_RULE_IDS = [EXPORT_CONFLICT_RULE, IMPORT_MISSING_RULE];

interface StackExports {
  stackName: string;
  stackConstructPath: string;
  templatePath: string;
  env: string;
  exports: Map<string, string>; // Export.Name -> Output の論理 ID
  imports: { name: string; logicalId: string }[];
}

/** 具体的でない環境は 1 つにまとめる（環境非依存のスタックは同じ CLI の環境にデプロイされる）。 */
function envKey(st: { accountId?: string; region?: string }): string {
  const account = isConcreteAccount(st.accountId) ? st.accountId : process.env.CDK_DEFAULT_ACCOUNT ?? '';
  const region = isConcreteRegion(st.region) ? st.region : process.env.CDK_DEFAULT_REGION ?? '';
  return `${account}/${region}`;
}

/** テンプレートの中の `Fn::ImportValue` のうち、名前が文字列のもの。 */
function findImports(node: unknown, logicalId: string, out: { name: string; logicalId: string }[]): void {
  if (Array.isArray(node)) {
    for (const x of node) findImports(x, logicalId, out);
    return;
  }
  if (node === null || typeof node !== 'object') return;
  for (const [k, v] of Object.entries(node)) {
    if (k === 'Fn::ImportValue' && typeof v === 'string') {
      out.push({ name: v, logicalId });
    } else {
      findImports(v, logicalId, out);
    }
  }
}

function readStacks(context: Pick<IPolicyValidationContext, 'stackTemplates'>): StackExports[] {
  const stacks: StackExports[] = [];
  for (const st of context.stackTemplates) {
    let template: any;
    try {
      template = JSON.parse(fs.readFileSync(st.templatePath, 'utf8'));
    } catch {
      continue; // 読めないテンプレートは他のプラグインが報告する
    }
    const exports = new Map<string, string>();
    for (const [id, o] of Object.entries<any>(template.Outputs ?? {})) {
      const name = o?.Export?.Name;
      if (typeof name === 'string') exports.set(name, id);
    }
    const imports: { name: string; logicalId: string }[] = [];
    for (const [id, r] of Object.entries<any>(template.Resources ?? {})) findImports(r, id, imports);
    for (const [id, o] of Object.entries<any>(template.Outputs ?? {})) findImports(o?.Value, id, imports);
    stacks.push({
      stackName: stackNameOf(st.templatePath),
      stackConstructPath: st.stackConstructPath,
      templatePath: st.templatePath,
      env: envKey(st),
      exports,
      imports,
    });
  }
  return stacks;
}

export function checkExports(
  context: Pick<IPolicyValidationContext, 'stackTemplates'>,
  opts: { severity: string; exclude?: string[] },
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const stacks = readStacks(context);
  const byEnv = new Map<string, StackExports[]>();
  for (const s of stacks) byEnv.set(s.env, [...(byEnv.get(s.env) ?? []), s]);

  for (const group of byEnv.values()) {
    // 1. 同じ環境で同じ Export.Name を持つスタックの組
    const owner = new Map<string, StackExports>();
    for (const s of group) {
      for (const [name, outputId] of s.exports) {
        const first = owner.get(name);
        if (!first) {
          owner.set(name, s);
          continue;
        }
        if (first.stackName === s.stackName) continue; // 同じスタック名 = 別環境の同名スタック（envKey が粗いとき）
        violations.push({
          ruleName: EXPORT_CONFLICT_RULE,
          description: `Stacks ${first.stackName} and ${s.stackName} deploy to the same account and Region and both export "${name}"; `
            + `export names must be unique there, so the second deploy fails with "Export with name ${name} is already exported by stack ${first.stackName}".`,
          severity: opts.severity,
          fix: 'Give one of the outputs a different exportName, or drop the explicit name and let CDK generate one.',
          violatingResources: [{
            resourceLogicalId: outputId,
            templatePath: s.templatePath,
            locations: [`Outputs/${outputId}/Export/Name`],
          }],
        });
      }
    }
    // 2. アプリ内のスタック名で始まる import 名を、そのスタックが export していない
    const byName = new Map(group.map((s) => [s.stackName, s]));
    for (const s of group) {
      for (const imp of s.imports) {
        const producer = byName.get(imp.name.split(':')[0]);
        if (!imp.name.includes(':') || !producer || producer.exports.has(imp.name)) continue;
        violations.push({
          ruleName: IMPORT_MISSING_RULE,
          description: `${s.stackName} imports "${imp.name}", but stack ${producer.stackName} in this app, which deploys to the same account `
            + `and Region, has no output exported under that name; the deploy fails with "No export named ${imp.name} found".`,
          severity: opts.severity,
          fix: `Export the value from ${producer.stackName} under this name (CfnOutput exportName), or reference the construct directly so CDK creates the export.`,
          violatingResources: [{
            resourceLogicalId: imp.logicalId,
            templatePath: s.templatePath,
            locations: [`Resources/${imp.logicalId}`],
          }],
        });
      }
    }
  }
  return violations.filter((v) => !opts.exclude?.includes(v.ruleName));
}

/**
 * スタック間の Export を検査するプラグイン。どちらのルールもまだ warning なので、enforce でも
 * observe でも同じプラグインで報告する（`cdk-preflight-exports::<rule-id>` で acknowledge）。
 */
export class PreflightExportPlugin implements IPolicyValidationPlugin {
  public readonly name = 'cdk-preflight-exports';

  constructor(private readonly exclude: string[] = []) {}

  public validate(context: IPolicyValidationContext): PolicyValidationPluginReport {
    return { success: true, violations: checkExports(context, { severity: 'warning', exclude: this.exclude }) };
  }
}
