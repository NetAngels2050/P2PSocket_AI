import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ClientRequest } from "node:http";

// 06 §6：hash 路由 + base './'（嵌入式静态托管）；产物直写宿主 wwwroot（08 §2②）
export default defineConfig({
  base: "./",
  plugins: [vue()],
  build: {
    outDir: "../../src/P2P.Client/wwwroot",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      // M5-12（07 §14.2）：本地服务随启动生成 web-token（重启轮换），开发代理代读文件注入
      // Bearer 头（WS 头载体服务端同收；每次请求现读=轮换后即时跟进）。文件缺失
      //（本地服务未跑过）跳过注入，请求将被 401——按 401 语义排障。
      "/api": {
        target: "http://127.0.0.1:7100",
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq: ClientRequest) => {
            const token = readLocalWebToken();
            if (token) proxyReq.setHeader("Authorization", `Bearer ${token}`);
          });
        },
      },
      "/ws": {
        target: "ws://127.0.0.1:7100",
        ws: true,
        configure: (proxy) => {
          proxy.on("proxyReqWs", (proxyReq: ClientRequest) => {
            const token = readLocalWebToken();
            if (token) proxyReq.setHeader("Authorization", `Bearer ${token}`);
          });
        },
      },
    },
  },
});

function readLocalWebToken(): string | null {
  const base = process.platform === "win32"
    ? join(process.env.ProgramData ?? "C:\\ProgramData", "P2PClient")
    : "/etc/p2p-client";
  try {
    return readFileSync(join(base, "web-token"), "utf8").trim() || null;
  } catch {
    return null; // 本地服务未跑过（无文件）
  }
}
