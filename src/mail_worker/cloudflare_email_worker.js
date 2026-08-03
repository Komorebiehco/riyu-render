/**
 * cloudflare_email_worker.js
 * Cloudflare Email Routing Worker — 极速接码引擎
 *
 * 部署方式：
 *   1. 在 Cloudflare Dashboard → Email Routing → Email Workers 中创建 Worker
 *   2. 将此脚本内容粘贴到 Worker 编辑器
 *   3. 在 Email Routing 规则中将 *@yourdomain.com 路由到此 Worker
 *   4. 在 Worker 环境变量中设置：
 *      CALLBACK_URL = http://your-server-ip:8765/code
 *      AUTH_TOKEN   = 与主程序约定的鉴权 Token
 *
 * 工作流程：
 *   Google 发送验证码邮件
 *     → Cloudflare 路由到此 Worker
 *     → 正则提取 6 位验证码
 *     → HTTP POST 推送到主程序回调接口
 *     → 主程序从 Redis 取码填入浏览器
 */

export default {
  async email(message, env, ctx) {
    const CALLBACK_URL = env.CALLBACK_URL || "http://127.0.0.1:8765/code";
    const AUTH_TOKEN   = env.AUTH_TOKEN   || "change-me-in-env";

    try {
      // ── 1. 读取邮件原始内容 ──────────────────────────────
      const rawEmail = await streamToText(message.raw);

      // ── 2. 解析收件人（用于区分是哪个账号的验证码）────────
      const toAddress   = message.to;      // e.g. acc_user123@yourdomain.com
      const fromAddress = message.from;    // e.g. no-reply@accounts.google.com

      // 只处理 Google 发出的邮件，其他一律忽略
      const isFromGoogle = (
        fromAddress.includes("google.com") ||
        fromAddress.includes("googlemail.com") ||
        fromAddress.includes("accounts.google.com")
      );
      if (!isFromGoogle) {
        console.log(`[SKIP] 非 Google 邮件: ${fromAddress}`);
        return;
      }

      // ── 3. 正则提取验证码 ───────────────────────────────
      // Google 验证码邮件格式多样，覆盖多种模板
      const codePatterns = [
        /\b([0-9]{6})\b(?=\s*(?:is your|是您的|為您的|verification|验证|驗證|code|码|碼))/i,
        /(?:verification code|验证码|驗證碼|安全码|安全碼)[^\d]*([0-9]{6})/i,
        /G-([0-9]{6})/i,          // Google 特定格式 "G-123456"
        /\b([0-9]{6})\b/,         // 兜底：提取第一个 6 位数字
      ];

      let verifyCode = null;
      for (const pattern of codePatterns) {
        const match = rawEmail.match(pattern);
        if (match) {
          verifyCode = match[1];
          break;
        }
      }

      // ── 4. 尝试提取重置链接（用于"忘记密码"找回流程）────
      let resetLink = null;
      const linkPatterns = [
        /https:\/\/accounts\.google\.com\/[^\s"'<>]+(?:reset|recovery|signin)[^\s"'<>]*/i,
        /https:\/\/myaccount\.google\.com\/[^\s"'<>]+/i,
      ];
      for (const pattern of linkPatterns) {
        const match = rawEmail.match(pattern);
        if (match) {
          resetLink = match[0].replace(/=\r?\n/g, "").replace(/=3D/g, "=");
          break;
        }
      }

      if (!verifyCode && !resetLink) {
        console.log(`[SKIP] 未提取到验证码或重置链接: to=${toAddress}`);
        return;
      }

      console.log(`[OK] to=${toAddress} code=${verifyCode} link=${resetLink ? "found" : "none"}`);

      // ── 5. 推送到主程序回调接口 ─────────────────────────
      const payload = {
        to:         toAddress,
        from:       fromAddress,
        code:       verifyCode,
        reset_link: resetLink,
        received_at: new Date().toISOString(),
      };

      const resp = await fetch(CALLBACK_URL, {
        method:  "POST",
        headers: {
          "Content-Type":  "application/json",
          "Authorization": `Bearer ${AUTH_TOKEN}`,
        },
        body: JSON.stringify(payload),
      });

      if (!resp.ok) {
        console.error(`[ERROR] 回调失败 HTTP ${resp.status}: ${await resp.text()}`);
      } else {
        console.log(`[PUSH] 验证码已推送: ${toAddress} → ${verifyCode}`);
      }

    } catch (err) {
      console.error(`[FATAL] Worker 异常: ${err.message}`);
    }
  },
};

// ── 辅助：ReadableStream → 文本字符串 ───────────────────────
async function streamToText(stream) {
  const reader  = stream.getReader();
  const chunks  = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const buffer = new Uint8Array(chunks.reduce((acc, c) => acc + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(buffer);
}
