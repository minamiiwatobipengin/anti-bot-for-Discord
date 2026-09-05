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
    try {
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
        if (!code) {
          return new Response("認証コードが見つかりません。最初からやり直してください。", { status: 400 });
        }

        // トークン取得（失敗時は処理中止）
        const tokenData = await exchangeCode(code, env);
        if (!tokenData || !tokenData.access_token) {
          return new Response("Discordトークンの取得に失敗しました。時間をおいて再試行してください。", { status: 500 });
        }

        // ユーザー情報取得（失敗時は処理中止）
        const user = await getDiscordUser(tokenData.access_token);
        if (!user || !user.id) {
          return new Response("Discordユーザー情報の取得に失敗しました。", { status: 500 });
        }

        return renderAuthPage(user.id, tokenData.access_token, guildId, env.HCAPTCHA_SITEKEY);
      }

      // 4. データ計測 & Discord へメタデータ送信
      if (url.pathname === "/verify" && request.method === "POST") {
        const formData = await request.formData();
        const hCaptchaResponse = formData.get("h-captcha-response") as string;
        const discordId = formData.get("discord_id") as string;
        const accessToken = formData.get("access_token") as string;
        const guildId = (formData.get("guild_id") as string) || "global";
        const clientIp = request.headers.get("cf-connecting-ip") || "";

        if (!discordId || !accessToken) {
          return new Response("不正なリクエストパラメータです。", { status: 400 });
        }

        // A. hCaptcha 検証 (例外が発生した場合は安全側「人間未認証 = 0」として扱う)
        let humanVerified = 0;
        if (hCaptchaResponse) {
          const isHuman = await verifyHCaptcha(hCaptchaResponse, env.HCAPTCHA_SECRET);
          if (isHuman) humanVerified = 1;
        }

        // B. IP / VPN / Proxy 検証
        // 【安全側に倒す】取得エラー・データ不整合時は安全のため vpnClean = 0 (リスクあり) とみなす
        let vpnClean = 0;
        try {
          const cfProps = (request as any).cf;
          const isProxyOrBot = checkIpThreatLevel(cfProps);
          const isTsukubaVpn = await checkTsukubaVpn(clientIp);

          // Proxy / Bot / 筑波大学VPNのいずれも検知されなかった場合のみ Clean (1) とする
          if (!isProxyOrBot && !isTsukubaVpn) {
            vpnClean = 1;
          }
        } catch (e) {
          console.error("VPN Check Failed -> Defaulting to Unsafe (Fail-Closed)", e);
          vpnClean = 0; // エラー時は判定を落とす（安全側）
        }

        // C. サブアカウント数のカウント（D1 取得エラー時は処理を中断）
        let subAccountNumber = 1;
        try {
          const existingRecords = await env.DB.prepare(
            "SELECT discord_id FROM users WHERE guild_id = ? AND verified_at IS NOT NULL"
          ).bind(guildId).all();

          if (!existingRecords || !existingRecords.results) {
            throw new Error("D1 query returned invalid result.");
          }

          const otherAccounts = existingRecords.results.filter((r: any) => r.discord_id !== discordId);
          subAccountNumber = otherAccounts.length + 1;
        } catch (e) {
          console.error("D1 Read Failed -> Aborting Process", e);
          return new Response("データベースエラーが発生したため認証処理を中止しました。", { status: 500 });
        }

        // D. DBの保存・更新（保存失敗時は処理を中断）
        const expiresAt = Math.floor(Date.now() / 1000) + 3600;
        try {
          await env.DB.prepare(
            `INSERT INTO users (discord_id, guild_id, access_token, refresh_token, expires_at, verified_at, last_ip)
             VALUES (?, ?, ?, 'N/A', ?, ?, ?)
             ON CONFLICT(discord_id, guild_id) DO UPDATE SET 
               access_token=?, expires_at=?, verified_at=?, last_ip=?`
          ).bind(
            discordId, guildId, accessToken, expiresAt, Math.floor(Date.now() / 1000), clientIp,
            accessToken, expiresAt, Math.floor(Date.now() / 1000), clientIp
          ).run();
        } catch (e) {
          console.error("D1 Write Failed -> Aborting Process", e);
          return new Response("データベースへの保存に失敗したため処理を中止しました。", { status: 500 });
        }

        // E. Discord へ全ステータス（メタデータ）を送信
        const updated = await updateRoleConnection(accessToken, {
          human_verified: humanVerified,
          vpn_clean: vpnClean,
          sub_account_number: subAccountNumber
        }, env);

        if (!updated) {
          return new Response("Discord Linked Role メタデータの更新に失敗しました。", { status: 500 });
        }

        return new Response("認証処理が完了しました！Discord画面に戻り、ロールの取得状況を確認してください。", {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }

      return Response.redirect(`${url.origin}/privacy`, 302);
    } catch (fatalError: any) {
      // 予期せぬクラッシュを捉えて Error 1101 を防ぎ、安全にエラーレスポンスを返す
      console.error("Unhandled Fatal Exception:", fatalError);
      return new Response(`システムエラーが発生しました: ${fatalError.message || "Unknown error"}`, { status: 500 });
    }
  }
};

/* --- メタデータ定義更新 (Discord 連携ロール設定画面用) --- */

async function handleUpdateMetadata(env: Env): Promise<Response> {
  try {
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

    if (!res.ok) {
      const errText = await res.text();
      return new Response(`メタデータ定義更新失敗: ${errText}`, { status: res.status });
    }

    return new Response("Discord Linked Role メタデータ定義を更新しました！", { status: 200 });
  } catch (e: any) {
    return new Response(`API通信エラー: ${e.message}`, { status: 500 });
  }
}

/* --- UI描画 --- */

function renderAuthPage(userId: string, accessToken: string, guildId: string, siteKey: string): Response {
  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Discord アカウント検証</title>
      <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #313338; color: white; margin: 0; }
        .card { background: #2b2d31; padding: 30px; border-radius: 8px; text-align: center; box-shadow: 0 4px 10px rgba(0,0,0,0.3); max-width: 400px; width: 90%; }
        button { margin-top: 15px; padding: 12px 20px; background: #5865F2; border: none; color: white; border-radius: 4px; font-weight: bold; cursor: pointer; width: 100%; font-size: 15px; }
        button:hover { background: #4752C4; }
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

/* --- 外部API通信 & セキュリティ判定（Fail-Closed 適用） --- */

async function exchangeCode(code: string, env: Env) {
  try {
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

    if (!res.ok) return null;
    return await res.json() as any;
  } catch (e) {
    console.error("exchangeCode Failed:", e);
    return null;
  }
}

async function getDiscordUser(accessToken: string) {
  try {
    const res = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!res.ok) return null;
    return await res.json() as any;
  } catch (e) {
    console.error("getDiscordUser Failed:", e);
    return null;
  }
}

async function verifyHCaptcha(token: string, secret: string): Promise<boolean> {
  if (!token) return false;
  try {
    const params = new URLSearchParams({ secret, response: token });
    const res = await fetch("https://hcaptcha.com/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString()
    });

    if (!res.ok) return false;
    const data = await res.json() as any;
    return !!data.success;
  } catch (e) {
    console.error("verifyHCaptcha Failed:", e);
    return false; // エラー時は認証失敗とみなす（安全側）
  }
}

function checkIpThreatLevel(cf: any): boolean {
  if (!cf || typeof cf !== "object") {
    // Cloudflare オブジェクトが取得できない環境（ローカル実行等）は警告として検知（安全側）
    return true; 
  }

  // RTTが0の場合は特殊プロキシ/Bot判定
  //if (cf.clientTcpRtt === 0) return true;

  const asOrg = cf.asOrganization || "";
  if (
    asOrg.includes("DigitalOcean") ||
    asOrg.includes("AWS") ||
    asOrg.includes("Hostinger") ||
    asOrg.includes("M247") ||
    asOrg.includes("Linode") ||
    asOrg.includes("Vultr")
  ) {
    return true; // ホスティング・プロキシと判断
  }

  return false;
}

async function checkTsukubaVpn(clientIp: string): Promise<boolean> {
  if (!clientIp) return true; // IPが取れない場合は安全のためブロック扱い

  try {
    const res = await fetch("https://www.vpngate.net/api/iphone/", {
      cf: { cacheTtl: 3600, cacheEverything: true }
    });

    if (!res.ok) {
      // 筑波大学APIが落ちている場合は安全側に倒して「VPNチェックでリスクあり」とする
      console.warn("Tsukuba VPN Gate API returned non-OK status.");
      return true;
    }

    const text = await res.text();
    const lines = text.split("\n");

    for (const line of lines) {
      if (line.startsWith("*") || line.startsWith("#") || !line.trim()) continue;
      const parts = line.split(",");
      if (parts.length > 1 && parts[1] === clientIp) {
        return true; // 筑波大学VPNに一致
      }
    }

    return false;
  } catch (e) {
    console.error("checkTsukubaVpn Failed:", e);
    return true; // 例外時は安全側に倒す
  }
}

async function updateRoleConnection(
  accessToken: string, 
  metadata: { human_verified: number; vpn_clean: number; sub_account_number: number }, 
  env: Env
): Promise<boolean> {
  try {
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
  } catch (e) {
    console.error("updateRoleConnection Failed:", e);
    return false;
  }
}