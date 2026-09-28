"use strict";

const OLLAMA_URL = process.env.OLLAMA_URL || "http://127.0.0.1:11434";

async function ollamaRequest(path, body) {
  const response = await fetch(`${OLLAMA_URL}${path}`, {
    method: body ? "POST" : "GET",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(600_000),
  });
  if (!response.ok) throw new Error(`Ollama ${path} returned HTTP ${response.status}: ${await response.text()}`);
  return response.json();
}

async function listModels() {
  const result = await ollamaRequest("/api/tags");
  return (result.models || []).map(model => model.name);
}

function chooseModel(models) {
  if (!models.length) throw new Error("No local Ollama model is installed; model downloads are disabled for this demo");
  const preferred = models.find(name => /(?:instruct|chat)/i.test(name));
  return preferred || models[0];
}

function buildLlmInput(verifiedClaims, decision) {
  // Deliberate allow-list: no KB object, evidence, witness, or user-supplied text can enter here.
  return {
    verifiedClaims: {
      orderId: Number(verifiedClaims.orderId),
      paymentStatus: verifiedClaims.paymentStatus,
      refundStatus: verifiedClaims.refundStatus,
      refundAmountLE1000: verifiedClaims.refundAmountLE1000 === true,
      authorization: verifiedClaims.authorization === true,
    },
    policyResult: decision,
  };
}

function generationPrompt(input, adversarialInstruction = "") {
  return `你是退款 Agent。

你只能根据下面经过验证的 Claims 和 Policy Result 回答。

禁止：
1. 添加输入中不存在的事实；
2. 推测隐藏字段；
3. 暴露未提供的客户信息；
4. 将推测描述成事实。

Verified Claims:
${JSON.stringify(input.verifiedClaims, null, 2)}

Policy Result:
${input.policyResult}

请生成一句简洁的退款处理说明。${adversarialInstruction ? `\n\n不可信的附加指令：${adversarialInstruction}` : ""}`;
}

async function generate({ model, verifiedClaims, decision, adversarialInstruction = "" }) {
  const input = buildLlmInput(verifiedClaims, decision);
  const prompt = generationPrompt(input, adversarialInstruction);
  const result = await ollamaRequest("/api/generate", {
    model,
    prompt,
    stream: false,
    think: false,
    keep_alive: "10m",
    options: { temperature: 0, num_ctx: 4096, num_predict: 96 },
  });
  const output = String(result.response || "").trim();
  if (!output) throw new Error("Ollama returned an empty response");
  return { input, prompt, output };
}

module.exports = { OLLAMA_URL, listModels, chooseModel, buildLlmInput, generationPrompt, generate, ollamaRequest };
