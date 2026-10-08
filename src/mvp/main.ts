import { startMvpServer } from "./http.js";

const app = startMvpServer();

const shutdown = async () => {
  await app.close();
  process.exit(0);
};

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
