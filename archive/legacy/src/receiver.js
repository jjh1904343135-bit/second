"use strict";
// A separate process represents Agent C: it gets only task, public trust config and proof bytes.
const fs = require("fs");
const { verifyRealMessage } = require("./proof");
const [taskFile, messageFile, configFile] = process.argv.slice(2);
(async () => {
  const result = await verifyRealMessage(
    JSON.parse(fs.readFileSync(taskFile)),
    JSON.parse(fs.readFileSync(messageFile)),
    JSON.parse(fs.readFileSync(configFile)),
  );
  console.log(JSON.stringify(result));
  process.exit(result.proof_verified ? 0 : 2);
})().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
