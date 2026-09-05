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

    // 0. プライバシーポリシー
    if (url.pathname === "/privacy") {
      return renderPrivacyPolicy();
    }

    // 1. Linked Role メタデータ定義更新 API (認証なし)
    if (url.pathname === "/update-metadata") {
      return await handleUpdateMetadata(env);
    }

    // 2. OAuth2 認証開始
    if (url.pathname === "/login") {
      const guildId = url.searchParams.get("guild_id") || "global";
      const authUrl = `https://discord.com/oauth2/authorize?client_id=${env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(env.DISCORD_REDIRECT_URI)}&response_type=code&scope=identify%20role_connections.write&state=${guildId}`;
      return Response.redirect(authUrl, 302);
    }

    // 3. OAuth2 コールバック受取 & 認証画面表示
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      const guildId = url.searchParams.get("state") || "global";
      if (!code) return new Response("Code missing", { status: 400 });

      const tokenData = await exchangeCode(code, env);
      if (!tokenData.access_token) return new Response("Failed to get token", { status: 400 });

      const user = await getDiscordUser(tokenData.access_token);

      return renderAuthPage(user.id, tokenData.access_token, guildId, env.HCAPTCHA_SITEKEY);
    }

    // 4. データ計測 & Discord へメタデータ送信（判定はすべて Discord 側へ一任）
    if (url.pathname === "/verify" && request.method === "POST") {
      const formData = await request.formData();
      const hCaptchaResponse = formData.get("h-captcha-response") as string;
      const discordId = formData.get("discord_id") as string;
      const accessToken = formData.get("access_token") as string;
      const guildId = (formData.get("guild_id") as string) || "global";
      const clientIp = request.headers.get("cf-connecting-ip") || "";

      // A. Captcha の実施結果判定（入力がなければ 0、クリアすれば 1）
      let humanVerified = 0;
      if (hCaptchaResponse) {
        const isHuman = await verifyHCaptcha(hCaptchaResponse, env.HCAPTCHA_SECRET);
        if (isHuman) humanVerified = 1;
      }

      // B. IP / VPN 検証（検知したかどうかだけを測定し、ここではエラーで弾かない）
      const cfProps = (request as any).cf;
      const isProxyOrBot = checkIpThreatLevel(cfProps);
      const isTsukubaVpn = await checkTsukubaVpn(clientIp);
      
      // VPNやProxyでなければ 1 (Clean)、使用していれば 0
      const vpnClean = (isProxyOrBot || isTsukubaVpn) ? 0 : 1;

      // C. 該当 Guild 内での登録順位の計算（1 = メインアカウント、2〜 = サブアカウント）
      const existingRecords = await env.DB.prepare(
        "SELECT discord_id FROM users WHERE guild_id = ? AND verified_at IS NOT NULL"
      ).bind(guildId).all();

      const otherAccounts = existingRecords.results.filter((r: any) => r.discord_id !== discordId);
      const subAccountNumber = otherAccounts.length + 1;

      // D. DBの保存・更新
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;
      await env.DB.prepare(
        `INSERT INTO users (discord_id, guild_id, access_token, refresh_token, expires_at, verified_at, last_ip)
         VALUES (?, ?, ?, 'N/A', ?, ?, ?)
         ON CONFLICT(discord_id, guild_id) DO UPDATE SET 
           access_token=?, expires_at=?, verified_at=?, last_ip=?`
      ).bind(
        discordId, guildId, accessToken, expiresAt, Math.floor(Date.now() / 1000), clientIp,
        accessToken, expiresAt, Math.floor(Date.now() / 1000), clientIp
      ).run();

      // E. Discord へ全ステータス（メタデータ）を送信
      const updated = await updateRoleConnection(accessToken, {
        human_verified: humanVerified,
        vpn_clean: vpnClean,
        sub_account_number: subAccountNumber
      }, env);

      if (!updated) return new Response("Discord Linked Role メタデータの更新に失敗しました。", { status: 500 });

      return new Response("認証処理が完了しました！Discord画面に戻り、ロールの取得状況を確認してください。", {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    return Response.redirect(`${url.origin}/privacy`, 302);
  }
};

/* --- メタデータ定義更新 (Discord 連携ロール設定画面用) --- */

async function handleUpdateMetadata(env: Env): Promise<Response> {
  const url = `https://discord.com/api/v10/applications/${env.DISCORD_CLIENT_ID}/role-connections/metadata`;
  
  const body = [
    {
      key: "human_verified",
      name: "人間認証 (hCaptcha) パス",
      description: "Captchaをクリアしているか",
      type: 7 // BOOLEAN_EQUAL (1 = True)
    },
    {
      key: "vpn_clean",
      name: "VPN / Proxy 未使用",
      description: "VPNや筑波大学VPNを使用していないか",
      type: 7 // BOOLEAN_EQUAL (1 = True)
    },
    {
      key: "sub_account_number",
      name: "アカウント順位 (サブ垢制限)",
      description: "メイン=1, サブ1=2, サブ2=3... (例: 1以下に設定でメインのみ許可)",
      type: 6 // NUMBER_LESS_THAN_OR_EQUAL
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
    ? new Response("Discord Linked Role メタデータ定義を更新しました！", { status: 200 })
    : new Response(`更新失敗: ${await res.text()}`, { status: res.status });
}

/* --- 画面描画 --- */

function renderAuthPage(userId: string, accessToken: string, guildId: string, siteKey: string): Response {
  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <title>Discord アカウント検証</title>
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
        <h2>Discord 連携認証</h2>
        <p style="font-size: 14px; color: #dbdee1;">下の Captcha を完了して「送信」を押してください。</p>
        
        <form action="/verify" method="POST">
          <input type="hidden" name="discord_id" value="${userId}" />
          <input type="hidden" name="access_token" value="${accessToken}" />
          <input type="hidden" name="guild_id" value="${guildId}" />

          <div class="h-captcha" data-sitekey="${siteKey}"></div>
          <button type="submit">送信して完了</button>
        </form>
        <div class="footer">
          <a href="/privacy" target="_blank">プライバシーポリシー</a>
        </div>
      </div>
    </body>
    </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function renderPrivacyPolicy(): Response {
  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <title>プライバシーポリシー</title>
      <style>
        body { font-family: sans-serif; line-height: 1.6; padding: 20px; max-width: 800px; margin: 0 auto; background: #1e1f22; color: #dbdee1; }
        .container { background: #2b2d31; padding: 30px; border-radius: 8px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>プライバシーポリシー</h1>
        <p>本認証システムは、Bot防止・接続元セキュリティ検証および連携ロール付与の目的でのみアカウント情報およびIP情報を処理します。</p>
      </div>
    </body>
    </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

/* --- API・データ通信 --- */

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
  if (!token) return false;
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
      if (parts.length > 1 && parts[1] === clientIp) return true;
    }
  } catch (e) {
    console.error("Failed to fetch Tsukuba VPN Gate data", e);
  }
  return false;
}

async function updateRoleConnection(
  accessToken: string, 
  metadata: { human_verified: number; vpn_clean: number; sub_account_number: number }, 
  env: Env
): Promise<boolean> {
  const url = `https://discord.com/api/v10/users/@me/applications/${env.DISCORD_CLIENT_ID}/role-connection`;
  const body = {
    platform_name: "Verification Service",
    metadata
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