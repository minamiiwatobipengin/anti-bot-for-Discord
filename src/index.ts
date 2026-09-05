export interface Env {
  DB: D1Database;
  DISCORD_CLIENT_ID: string;
  DISCORD_CLIENT_SECRET: string;
  DISCORD_REDIRECT_URI: string;
  DISCORD_BOT_TOKEN: string;
  HCAPTCHA_SECRET: string;
  HCAPTCHA_SITEKEY: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // 0. プライバシーポリシーページ
    if (url.pathname === "/privacy") {
      return renderPrivacyPolicy();
    }

    // 1. Linked Role メタデータ定義更新API (認証なし)
    if (url.pathname === "/update-metadata") {
      return await handleUpdateMetadata(env);
    }

    // 2. OAuth2 認証開始 (Discordログイン画面へ)
    if (url.pathname === "/login") {
      const authUrl = `https://discord.com/oauth2/authorize?client_id=${env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(env.DISCORD_REDIRECT_URI)}&response_type=code&scope=identify%20role_connections.write`;
      return Response.redirect(authUrl, 302);
    }

    // 3. OAuth2 コールバック受取 & 認証画面（hCaptcha）表示
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      if (!code) return new Response("Code missing", { status: 400 });

      const tokenData = await exchangeCode(code, env);
      if (!tokenData.access_token) return new Response("Failed to get token", { status: 400 });

      const user = await getDiscordUser(tokenData.access_token);

      const expiresAt = Math.floor(Date.now() / 1000) + tokenData.expires_in;
      await env.DB.prepare(
        `INSERT INTO users (discord_id, access_token, refresh_token, expires_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(discord_id) DO UPDATE SET access_token=?, refresh_token=?, expires_at=?`
      ).bind(
        user.id, tokenData.access_token, tokenData.refresh_token, expiresAt,
        tokenData.access_token, tokenData.refresh_token, expiresAt
      ).run();

      return renderCaptchaPage(user.id, tokenData.access_token, env.HCAPTCHA_SITEKEY);
    }

    // 4. Captcha & IP/VPN 検証実行
    if (url.pathname === "/verify" && request.method === "POST") {
      const formData = await request.formData();
      const hCaptchaResponse = formData.get("h-captcha-response") as string;
      const discordId = formData.get("discord_id") as string;
      const accessToken = formData.get("access_token") as string;
      const clientIp = request.headers.get("cf-connecting-ip") || "";

      // Captcha 検証
      const isHuman = await verifyHCaptcha(hCaptchaResponse, env.HCAPTCHA_SECRET);
      if (!isHuman) return new Response("Captcha Verification Failed", { status: 400 });

      // IP/VPN チェック
      const cfProps = (request as any).cf;
      const isProxyOrBot = checkIpThreatLevel(cfProps);
      const isTsukubaVpn = await checkTsukubaVpn(clientIp);

      if (isProxyOrBot || isTsukubaVpn) {
        return new Response("VPN, Proxy, または筑波大学VPNからの接続は許可されていません。VPNをオフにして再試行してください。", { status: 403 });
      }

      // Discord Linked Role メタデータ更新
      const updated = await updateRoleConnection(discordId, accessToken, env);
      if (!updated) return new Response("Failed to update Discord Linked Role", { status: 500 });

      await env.DB.prepare(
        "UPDATE users SET verified_at = ?, last_ip = ? WHERE discord_id = ?"
      ).bind(Math.floor(Date.now() / 1000), clientIp, discordId).run();

      return new Response("認証が完了しました！Discord画面に戻り、連携ロールを獲得してください。", {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    return Response.redirect(`${url.origin}/privacy`, 302);
  }
};

/* --- 補助関数・画面描画 --- */

// プライバシーポリシー画面 HTML
function renderPrivacyPolicy(): Response {
  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <title>プライバシーポリシー - Discord Bot Verification</title>
      <style>
        body { font-family: sans-serif; line-height: 1.6; padding: 20px; max-width: 800px; margin: 0 auto; background: #1e1f22; color: #dbdee1; }
        h1, h2 { color: #f2f3f5; border-bottom: 1px solid #4e5058; padding-bottom: 8px; }
        a { color: #00a8fc; }
        .container { background: #2b2d31; padding: 30px; border-radius: 8px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>プライバシーポリシー</h1>
        <p>本システム（以下「当サービス」）は、Discord サーバーにおけるスパム・Bot・不審な接続を防止するための認証システムです。当サービスをご利用いただくにあたり、以下のプライバシーポリシーをご確認ください。</p>

        <h2>1. 収集する情報</h2>
        <ul>
          <li><strong>Discord アカウント情報:</strong> ユーザーID、OAuth2 アクセストークン・リフレッシュトークン。</li>
          <li><strong>接続・ネットワーク情報:</strong> 接続元 IP アドレス、ASN（自律システム番号）、ホスティング/VPN 識別情報。</li>
          <li><strong>hCaptcha 検証データ:</strong> hCaptcha サービスにより処理される判定結果。</li>
        </ul>

        <h2>2. 情報の利用目的</h2>
        <ul>
          <li>Bot および自動化プログラムのアクセス排除。</li>
          <li>VPN、Proxy、ならびに公開 VPN サーバーからの接続検知・遮断。</li>
          <li>Discord の「連携ロール (Linked Roles)」機能を通じたロール付与資格の確認。</li>
        </ul>

        <h2>3. データの保管期間と第三者提供</h2>
        <p>取得したデータは認証状態の維持および不正防御の目的のみに使用し、法令に基づく開示要請がある場合を除き、第三者へ売却または提供することはありません。</p>

        <h2>4. データの削除請求</h2>
        <p>保管データの削除を希望される場合は、サポートサーバーにお問い合わせください.早急に削除いたします.https://discord.gg/T88BvqhSV</p>
      </div>
    </body>
    </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// Captcha UI HTML
function renderCaptchaPage(userId: string, accessToken: string, siteKey: string): Response {
  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <title>人間・安全接続の確認</title>
      <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
      <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #313338; color: white; margin: 0; }
        .card { background: #2b2d31; padding: 30px; border-radius: 8px; text-align: center; box-shadow: 0 4px 10px rgba(0,0,0,0.3); max-width: 400px; }
        button { margin-top: 15px; padding: 10px 20px; background: #5865F2; border: none; color: white; border-radius: 4px; font-weight: bold; cursor: pointer; width: 100%; }
        .footer { margin-top: 15px; font-size: 12px; color: #949ba4; }
        .footer a { color: #00a8fc; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>安全接続チェック</h2>
        <p style="font-size: 14px; color: #dbdee1;">認証を完了するため Captcha を解除してください。<br><small>※VPNを有効にしている場合はオフにしてください。</small></p>
        <form action="/verify" method="POST">
          <input type="hidden" name="discord_id" value="${userId}" />
          <input type="hidden" name="access_token" value="${accessToken}" />
          <div class="h-captcha" data-sitekey="${siteKey}"></div>
          <button type="submit">認証してロールを獲得</button>
        </form>
        <div class="footer">
          続行することで <a href="/privacy" target="_blank">プライバシーポリシー</a> に同意したものとみなされます。
        </div>
      </div>
    </body>
    </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

/* --- バックエンド処理ロジック (前述と同様) --- */

async function handleUpdateMetadata(env: Env): Promise<Response> {
  const url = `https://discord.com/api/v10/applications/${env.DISCORD_CLIENT_ID}/role-connections/metadata`;
  const body = [
    {
      key: "human_verified",
      name: "Human Verified",
      description: "hCaptcha and Anti-VPN Check Passed",
      type: 7
    }
  ];

  const res = await fetch(url, {
    method: "PUT",
    headers: {
      "Authorization": `Bot ${env.DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  return res.ok 
    ? new Response("Discord Linked Role Metadata Schema Updated Successfully!", { status: 200 })
    : new Response(`Failed to update schema: ${await res.text()}`, { status: res.status });
}

async function exchangeCode(code: string, env: Env) {
  const params = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    client_secret: env.DISCORD_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: env.DISCORD_REDIRECT_URI
  });

  const res = await fetch("https://discord.com/api/v10/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString()
  });
  return await res.json() as any;
}

async function getDiscordUser(accessToken: string) {
  const res = await fetch("https://discord.com/api/v10/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  return await res.json() as any;
}

async function verifyHCaptcha(token: string, secret: string): Promise<boolean> {
  const params = new URLSearchParams({ secret, response: token });
  const res = await fetch("https://hcaptcha.com/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString()
  });
  const data = await res.json() as any;
  return data.success;
}

function checkIpThreatLevel(cf: any): boolean {
  if (!cf) return false;
  if (cf.clientTcpRtt === 0) return true;
  if (cf.asOrganization && (
      cf.asOrganization.includes("DigitalOcean") ||
      cf.asOrganization.includes("AWS") ||
      cf.asOrganization.includes("Hostinger") ||
      cf.asOrganization.includes("M247")
  )) {
    return true;
  }
  return false;
}

async function checkTsukubaVpn(clientIp: string): Promise<boolean> {
  try {
    const res = await fetch("https://www.vpngate.net/api/iphone/", {
      cf: { cacheTtl: 3600, cacheEverything: true }
    });
    const text = await res.text();
    const lines = text.split("\n");
    
    for (const line of lines) {
      if (line.startsWith("*") || line.startsWith("#") || !line.trim()) continue;
      const parts = line.split(",");
      if (parts.length > 1 && parts[1] === clientIp) {
        return true;
      }
    }
  } catch (e) {
    console.error("Failed to fetch Tsukuba VPN Gate data", e);
  }
  return false;
}

async function updateRoleConnection(userId: string, accessToken: string, env: Env): Promise<boolean> {
  const url = `https://discord.com/api/v10/users/@me/applications/${env.DISCORD_CLIENT_ID}/role-connection`;
  const body = {
    platform_name: "Anti-VPN Verification",
    metadata: { human_verified: 1 }
  };

  const res = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  return res.ok;
}