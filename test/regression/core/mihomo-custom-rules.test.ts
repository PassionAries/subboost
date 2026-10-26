import { describe, expect, it } from "vitest";
import { load } from "js-yaml";
import { CUSTOM_RULE_TYPES, getCustomRuleDefinition, hasCommaPayload, isCustomRuleType, supportsNoResolve } from "../../../packages/core/src/rules/custom-rule-types";
import { normalizeCustomRuleValue, normalizeLogicRulePayload } from "../../../packages/core/src/rules/custom-rule-value";
import { parseCustomRuleBatchImport } from "../../../packages/core/src/rules/custom-rule-batch-import";
import { buildGenerateOptionsFromConfig } from "../../../packages/core/src/subscription/config-utils";
import { generateClashConfig } from "../../../packages/core/src/generator";
import { configToYaml } from "../../../packages/core/src/generator/yaml";
import { validateSubBoostTemplateConfig } from "../../../packages/core/src/templates/config-template";
import { validConfig } from "../../../packages/core/src/templates/config-template.test-helpers";

function parse(text: string, defaultType: (typeof CUSTOM_RULE_TYPES)[number] = "DOMAIN") {
  return parseCustomRuleBatchImport({ text, defaultType, defaultTarget: "DIRECT", defaultNoResolve: true, targetOptions: ["DIRECT", "REJECT"], existingRules: [] });
}

describe("Mihomo stable custom rule round trips", () => {
  it.each(CUSTOM_RULE_TYPES)("preserves %s through import, template, saved JSON and YAML", (type) => {
    const value = getCustomRuleDefinition(type).example;
    const imported = parse(`${type},${value},DIRECT${supportsNoResolve(type) ? ",no-resolve" : ""}`);
    expect(imported.canImport).toBe(true);
    const template = validateSubBoostTemplateConfig(validConfig({ customRules: imported.rules }));
    expect(template.ok).toBe(true);
    if (!template.ok) throw new Error(template.error);
    const options = buildGenerateOptionsFromConfig(JSON.parse(JSON.stringify({
      template: "full", enabledGroups: [], enabledRules: [], customRules: template.config.customRules,
    })), { nodes: [] });
    const rule = options.userConfig?.customRules?.[0];
    expect(rule).toMatchObject({ type, value, noResolve: supportsNoResolve(type) });
    const yaml = load(configToYaml(generateClashConfig(options))) as { rules: string[] };
    expect(yaml.rules).toContain(`${type},${value},DIRECT${supportsNoResolve(type) ? ",no-resolve" : ""}`);
  });

  it("keeps regex commas, balanced parentheses, case flags, quotes and Windows paths", () => {
    const regex = String.raw`(?i)^(foo|bar){1,3}\\app"name\.exe$`;
    expect(parse(`PROCESS-PATH-REGEX,${regex},REJECT`).rules[0]).toMatchObject({ value: regex, target: "REJECT" });
    expect(parse('DOMAIN-REGEX,"quoted",DIRECT').rules[0]?.value).toBe('"quoted"');
    expect(parse('"DOMAIN-REGEX","quoted,regex",DIRECT', "AND").rules[0]?.value).toBe("quoted,regex");
    expect(parse(regex, "PROCESS-PATH-REGEX").rules[0]?.value).toBe(regex);
    const path = String.raw`C:\Program Files\App (x64)\app.exe`;
    expect(parse(`PROCESS-PATH,${path},DIRECT`).rules[0]?.value).toBe(path);
    const logical = `((DOMAIN-REGEX,^(foo|bar){1,3}\\.test$),(PROCESS-PATH,${path}))`;
    expect(normalizeLogicRulePayload("AND", logical)).toEqual({ ok: true, value: logical });
    expect(parse(`AND,${logical},DIRECT`).rules[0]?.value).toBe(logical);
  });

  it("accepts single-child AND/OR, nested conditions, lowercase types and IP parameters", () => {
    expect(normalizeLogicRulePayload("AND", "((NETWORK,udp))").ok).toBe(true);
    expect(normalizeLogicRulePayload("OR", "((AND,((network,tcp))))")).toEqual({ ok: true, value: "((AND,((NETWORK,tcp))))" });
    const value = "((IP-ASN,64512,src),(IP-SUFFIX,203.0.113.1/24,no-resolve),(RULE-SET,configured,src))";
    expect(normalizeLogicRulePayload("OR", value)).toEqual({ ok: true, value });
  });

  it.each([
    ["AND", "()"], ["AND", "((NETWORK,tcp)),((NETWORK,udp))"],
    ["OR", "((UNKNOWN,x))"], ["OR", "((SUB-RULE,x))"],
    ["OR", "((NETWORK,tcp,no-resolve))"], ["OR", "((IP-CIDR,203.0.113.0/24,invalid))"],
    ["DOMAIN", "a,b"], ["DOMAIN", "a\nb"], ["PROCESS-PATH", "a\0b"],
  ])("rejects unsafe or invalid structure: %s %s", (type, value) => {
    expect(normalizeCustomRuleValue(type, value).ok).toBe(false);
  });

  it("does not add no-resolve to source IP, domain, process or logic rules", () => {
    for (const type of ["SRC-IP-CIDR", "DOMAIN", "PROCESS-NAME", "AND"] as const) {
      const value = getCustomRuleDefinition(type).example;
      const result = validateSubBoostTemplateConfig(validConfig({ customRules: [{ id: type, type, value, target: "DIRECT", noResolve: true }] }));
      expect(result.ok && result.config.customRules[0].noResolve).toBe(false);
    }
    expect(supportsNoResolve("RULE-SET")).toBe(true);
    expect(supportsNoResolve("unknown")).toBe(false);
    expect(hasCommaPayload("unknown")).toBe(false);
    expect(isCustomRuleType("MATCH")).toBe(false);
    expect(isCustomRuleType("SUB-RULE")).toBe(false);
    expect(isCustomRuleType("toString")).toBe(false);
  });

  it("canonicalizes imported type names and compares legacy flags by their effect", () => {
    expect(parse("domain,local.subboost.test,DIRECT").rules[0]?.type).toBe("DOMAIN");
    const result = parseCustomRuleBatchImport({ text: "DOMAIN,local.subboost.test,DIRECT", defaultType: "DOMAIN", defaultTarget: "DIRECT", defaultNoResolve: false, targetOptions: ["DIRECT"], existingRules: [{ id: "old", type: "DOMAIN", value: "local.subboost.test", target: "DIRECT", noResolve: true }] });
    expect(result.duplicateCount).toBe(1);
  });
});
