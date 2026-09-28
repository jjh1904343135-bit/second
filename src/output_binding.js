"use strict";

const { ollamaRequest } = require("./llm_agent");

function verifierPrompt(verifiedClaims, decision, output) {
  return `你是事实一致性验证器。

给定：
1. 已验证 Claims；
2. Policy Result；
3. Agent 自然语言输出。

请判断自然语言输出中的每一个事实性陈述是否都能够由已验证 Claims 或 Policy Result 支持。

不要使用外部知识。
不要推测。
只判断输入之间的支持关系。

Verified Claims:
${JSON.stringify(verifiedClaims, null, 2)}

Policy Result:
${decision}

判定规则补充：Policy Result 为 APPROVED 时，直接支持“退款获批”“退款条件满足”等同义陈述；
orderId 直接支持对应订单编号。不要因为自然语言使用同义表达而判为不支持。
如果输出出现输入中没有的属性（例如信用、年龄、姓名、风险等级），该陈述必须标为 UNSUPPORTED。
顶层 supported 与逐条 status 必须一致；supported=false 时至少一条 status 必须是 UNSUPPORTED。

Agent Output:
${JSON.stringify(output)}

返回严格 JSON：
{
  "supported": true,
  "claims": [
    { "text": "事实性陈述", "status": "SUPPORTED" }
  ]
}

若任何陈述没有直接支持，supported 必须为 false，且对应 status 必须为 "UNSUPPORTED"。`;
}

function normalize(result) {
  if (!result || typeof result !== "object" || !Array.isArray(result.claims)) {
    throw new Error("Verifier response does not match the required JSON shape");
  }
  const claims = result.claims.map(item => ({
    text: String(item.text || ""),
    status: item.status === "SUPPORTED" ? "SUPPORTED" : "UNSUPPORTED",
  }));
  // Fail closed: the list determines the verdict; a contradictory top-level flag cannot pass.
  const supported = result.supported === true && claims.length > 0 && claims.every(item => item.status === "SUPPORTED");
  return { supported, claims };
}

async function checkOutputBinding({ model, verifiedClaims, decision, output }) {
  const prompt = verifierPrompt(verifiedClaims, decision, output);
  const schema = {
    type: "object",
    properties: {
      supported: { type: "boolean" },
      claims: {
        type: "array",
        minItems: 1,
        items: {
          type: "object",
          properties: {
            text: { type: "string" },
            status: { type: "string", enum: ["SUPPORTED", "UNSUPPORTED"] },
          },
          required: ["text", "status"],
          additionalProperties: false,
        },
      },
    },
    required: ["supported", "claims"],
    additionalProperties: false,
  };
  const response = await ollamaRequest("/api/generate", {
    model,
    prompt,
    stream: false,
    format: schema,
    think: false,
    keep_alive: "10m",
    options: { temperature: 0, num_ctx: 4096, num_predict: 256 },
  });
  let parsed;
  try {
    parsed = JSON.parse(response.response);
  } catch (error) {
    throw new Error(`Verifier returned invalid JSON: ${error.message}`);
  }
  try {
    return { prompt, raw: response.response, result: normalize(parsed) };
  } catch (error) {
    throw new Error(`${error.message}; raw verifier response: ${response.response}`);
  }
}

module.exports = { verifierPrompt, normalize, checkOutputBinding };
