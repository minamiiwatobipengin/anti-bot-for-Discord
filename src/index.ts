const ADMIN_DISCORD_ID = "1506950854249418765";

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const cookies = parseCookies(request.headers.get("Cookie") || "");

      // 0-1. プライバシーポリシー
      if (url.pathname === "/privacy") {
        return renderPrivacyPolicy(url.origin);
      }

      // 0-2. 利用規約
      if (url.pathname === "/terms") {
        return renderTermsOfService();
      }

      // 0-3. ユーザー自身のデータ削除リクエスト
      if (url.pathname === "/delete-my-data") {
        return await handleDeleteMyData(request, cookies, env);
      }

      // 1. Linked Role メタデータ定義更新 API (Bot管理者用)
      if (url.pathname === "/update-metadata") {
        return await handleUpdateMetadata(env);
      }

      // 2. OAuth2 認証開始 (CSRF防止用 state の生成と Cookie 設定)
      if (url.pathname === "/login") {
        const guildId = url.searchParams.get("guild_id") || "global";
        const stateToken = crypto.randomUUID();
        const statePayload = `${guildId}:${stateToken}`;

        const authUrl = `https://discord.com/oauth2/authorize?client_id=${
          env.DISCORD_CLIENT_ID
        }&redirect_uri=${encodeURIComponent(
          env.DISCORD_REDIRECT_URI
        )}&response_type=code&scope=identify%20role_connections.write&state=${encodeURIComponent(statePayload)}`;

        const headers = new Headers();
        headers.set("Location", authUrl);
        headers.append(
          "Set-Cookie",
          `oauth_state=${stateToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
        );

        return new Response(null, {
          status: 302,
          headers: headers
        });
      }

      // 3. OAuth2 コールバック受取 & 認証・同意画面表示
      if (url.pathname === "/callback") {
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");

        if (!code || !state) {
          return new Response("認証パラメータが不足しています。", { status: 400 });
        }

        const [guildId, stateToken] = state.split(":");
        const savedState = cookies["oauth_state"];

        if (!savedState || savedState !== stateToken) {
          return new Response("無効なセッションまたはCSRFトークンの検証に失敗しました。", { status: 403 });
        }

        const tokenData = await exchangeCode(code, env);
        if (!tokenData || !tokenData.access_token) {
          return new Response("Discordトークンの取得に失敗しました。", { status: 500 });
        }

        const user = await getDiscordUser(tokenData.access_token);
        if (!user || !user.id) {
          return new Response("Discordユーザー情報の取得に失敗しました。", { status: 500 });
        }

        const sessionPayload = JSON.stringify({
          userId: user.id,
          accessToken: tokenData.access_token,
          guildId: guildId || "global"
        });

        const response = renderAuthPage(user.id, env.HCAPTCHA_SITEKEY, user.id === ADMIN_DISCORD_ID);
        response.headers.append(
          "Set-Cookie",
          `v_sess=${encodeURIComponent(sessionPayload)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=600`
        );
        response.headers.append("Set-Cookie", "oauth_state=; Path=/; HttpOnly; Secure; Max-Age=0");

        return response;
      }

      // 4. データ計測 & Discord へメタデータ送信
      if (url.pathname === "/verify" && request.method === "POST") {
        const sessCookie = cookies["v_sess"];
        if (!sessCookie) {
          return new Response("セッションの期限が切れているか無効です。最初からやり直してください。", { status: 401 });
        }

        let session;
        try {
          session = JSON.parse(decodeURIComponent(sessCookie));
        } catch (e) {
          return new Response("無効なセッションデータです。", { status: 400 });
        }

        const formData = await request.formData();
        const hCaptchaResponse = formData.get("h-captcha-response");
        const termsAgreed = formData.get("terms_agreed");
        const clientIp = request.headers.get("cf-connecting-ip") || "";

        if (!termsAgreed) {
          return new Response("利用規約およびプライバシーポリシーへの同意が必要です。", { status: 400 });
        }

        const discordId = session.userId;
        const accessToken = session.accessToken;
        const guildId = session.guildId;

        let humanVerified = 0;
        if (hCaptchaResponse) {
          const isHuman = await verifyHCaptcha(hCaptchaResponse, env.HCAPTCHA_SECRET);
          if (isHuman) humanVerified = 1;
        }

        let vpnClean = 0;
        try {
          const isProxyOrBotOrTor = checkIpThreatLevel(request);
          const isTsukubaVpn = await checkTsukubaVpn(clientIp);

          if (!isProxyOrBotOrTor && !isTsukubaVpn) {
            vpnClean = 1;
          }
        } catch (e) {
          vpnClean = 0;
        }

        let deviceId = cookies["device_id"];
        if (!deviceId) {
          deviceId = crypto.randomUUID();
        }

        let subAccountNumber = 1;
        try {
          const existingRecords = await env.DB.prepare(
            "SELECT discord_id, device_id FROM users WHERE guild_id = ? AND verified_at IS NOT NULL"
          ).bind(guildId).all();

          if (existingRecords && existingRecords.results) {
            const otherAccounts = existingRecords.results.filter(
              (r) => r.discord_id !== discordId && (r.device_id === deviceId)
            );
            subAccountNumber = otherAccounts.length + 1;
          }
        } catch (e) {
          return new Response("データベースエラーが発生しました。", { status: 500 });
        }

        const expiresAt = Math.floor(Date.now() / 1000) + 3600;
        try {
          await env.DB.prepare(
            `INSERT INTO users (discord_id, guild_id, access_token, refresh_token, expires_at, verified_at, last_ip, device_id)
             VALUES (?, ?, ?, 'N/A', ?, ?, ?, ?)
             ON CONFLICT(discord_id, guild_id) DO UPDATE SET 
               access_token=?, expires_at=?, verified_at=?, last_ip=?, device_id=?`
          ).bind(
            discordId, guildId, accessToken, expiresAt, Math.floor(Date.now() / 1000), clientIp, deviceId,
            accessToken, expiresAt, Math.floor(Date.now() / 1000), clientIp, deviceId
          ).run();
        } catch (e) {
          return new Response("データベースへの保存に失敗しました。", { status: 500 });
        }

        const updated = await updateRoleConnection(accessToken, {
          human_verified: humanVerified,
          vpn_clean: vpnClean,
          sub_account_number: subAccountNumber
        }, env);

        if (!updated) {
          return new Response("Discord Linked Role メタデータの更新に失敗しました。", { status: 500 });
        }

        const res = new Response(`<html>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
              <h1>このタブを安全に閉じることができます</h1><script>window.close()</script>
            </body>
          </html>`, {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });

        res.headers.append(
          "Set-Cookie",
          `device_id=${deviceId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`
        );
        res.headers.append("Set-Cookie", "v_sess=; Path=/; HttpOnly; Secure; Max-Age=0");

        return res;
      }

      // 5. 管理者用 全員アンリンク API
      if (url.pathname === "/admin/unlink-all" && request.method === "POST") {
        const sessCookie = cookies["v_sess"];
        if (!sessCookie) {
          return new Response("管理者セッションが見つかりません。先に /login から管理者アカウントでログインしてください。", { status: 401 });
        }

        let session;
        try {
          session = JSON.parse(decodeURIComponent(sessCookie));
        } catch (e) {
          return new Response("無効なセッションです。", { status: 400 });
        }

        if (session.userId !== ADMIN_DISCORD_ID) {
          return new Response("アクセス権限がありません。管理者IDのみ実行可能です。", { status: 403 });
        }

        const { results } = await env.DB.prepare("SELECT discord_id, access_token FROM users").all();
        let successCount = 0;
        let failCount = 0;

        if (results && results.length > 0) {
          for (const user of results) {
            const ok = await updateRoleConnection(user.access_token, {}, env);
            if (ok) {
              successCount++;
            } else {
              failCount++;
            }
          }
        }

        await env.DB.prepare("DELETE FROM users").run();

        return new Response(`[管理者処理完了]\nアンリンク成功: ${successCount}件\n失敗(トークン切れ等): ${failCount}件\nDBの検証データを削除しました。`, {
          headers: { "Content-Type": "text/plain; charset=utf-8" }
        });
      }

      return Response.redirect(`${url.origin}/privacy`, 302);
    } catch (fatalError) {
      return new Response(`システムエラーが発生しました: ${fatalError.message || "Unknown error"}`, { status: 500 });
    }
  }
};

/* --- ユーザー自身のデータ削除処理 --- */

async function handleDeleteMyData(request, cookies, env) {
  const sessCookie = cookies["v_sess"];
  if (!sessCookie) {
    return new Response(`
      <html>
        <body style="font-family: sans-serif; text-align: center; padding-top: 50px; background: #1e1f22; color: #dbdee1;">
          <h2>認証情報が見つかりません</h2>
          <p>データを削除するには、一度 <a href="/login" style="color: #00a8fc;">ログイン (認証)</a> を行う必要があります。</p>
        </body>
      </html>
    `, { headers: { "Content-Type": "text/html; charset=utf-8" }, status: 401 });
  }

  let session;
  try {
    session = JSON.parse(decodeURIComponent(sessCookie));
  } catch (e) {
    return new Response("無効なセッションです。", { status: 400 });
  }

  // 1. Discordの連携メタデータをクリア
  await updateRoleConnection(session.accessToken, {}, env);

  // 2. データベースからユーザーレコードを削除
  try {
    await env.DB.prepare("DELETE FROM users WHERE discord_id = ?").bind(session.userId).run();
  } catch (e) {
    return new Response("データベース上のデータ削除に失敗しました。", { status: 500 });
  }

  // 3. クッキーを消去して完了レスポンスを返す
  const res = new Response(`
    <html>
      <body style="font-family: sans-serif; text-align: center; padding-top: 50px; background: #1e1f22; color: #dbdee1;">
        <h1>データ削除完了</h1>
        <p>あなたの認証データおよびDiscord連携情報を正常に削除しました。</p>
      </body>
    </html>
  `, { headers: { "Content-Type": "text/html; charset=utf-8" } });

  res.headers.append("Set-Cookie", "v_sess=; Path=/; HttpOnly; Secure; Max-Age=0");
  res.headers.append("Set-Cookie", "device_id=; Path=/; HttpOnly; Secure; Max-Age=0");

  return res;
}

/* --- メタデータ定義更新 --- */

async function handleUpdateMetadata(env) {
  try {
    const url = `https://discord.com/api/v10/applications/${env.DISCORD_CLIENT_ID}/role-connections/metadata`;
    
    const body = [
      {
        key: "human_verified",
        name: "人間認証 (hCaptcha) パス",
        description: "Captchaをクリアしているか",
        type: 7
      },
      {
        key: "vpn_clean",
        name: "VPN / Proxy / Tor 未使用",
        description: "VPN・Tor・プロキシ・筑波大学VPN等を使用していないか",
        type: 7
      },
      {
        key: "sub_account_number",
        name: "アカウント順位 (サブ垢制限)",
        description: "メイン=1, サブ1=2, サブ2=3... (例: 1以下に設定でメインのみ許可)",
        type: 6
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
  } catch (e) {
    return new Response(`API通信エラー: ${e.message}`, { status: 500 });
  }
}

/* --- UI描画 --- */

function renderAuthPage(userId, siteKey, isAdmin = false) {
  const adminPanel = isAdmin ? `
    <div style="margin-top: 25px; padding-top: 15px; border-top: 1px solid #4e5058;">
      <p style="color: #ed4245; font-weight: bold; font-size: 13px;">管理者用メニュー (${ADMIN_DISCORD_ID})</p>
      <button type="button" onclick="unlinkAllUsers()" style="background: #da373c; margin-top: 5px;">⚠️ 全全員の連携解除 (全員アンリンク)</button>
    </div>
    <script>
      async function unlinkAllUsers() {
        if (!confirm('本当にデータベース内の全ユーザーの連携（ロールメタデータ）を解除しますか？')) return;
        const res = await fetch('/admin/unlink-all', { method: 'POST' });
        const text = await res.text();
        alert(text);
      }
    </script>
  ` : '';

  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Discord アカウント検証</title>
      <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #313338; color: white; margin: 0; padding: 20px 0; box-sizing: border-box; }
        .card { background: #2b2d31; padding: 30px; border-radius: 8px; text-align: center; box-shadow: 0 4px 10px rgba(0,0,0,0.3); max-width: 420px; width: 90%; }
        .checkbox-container { display: flex; align-items: center; justify-content: center; gap: 8px; margin: 15px 0; font-size: 13px; cursor: pointer; }
        .checkbox-container input { cursor: pointer; width: 16px; height: 16px; }
        button { margin-top: 10px; padding: 12px 20px; background: #5865F2; border: none; color: white; border-radius: 4px; font-weight: bold; cursor: pointer; width: 100%; font-size: 15px; }
        button:disabled { background: #4e5058; cursor: not-allowed; }
        button:hover:not(:disabled) { background: #4752C4; }
        .footer { margin-top: 15px; font-size: 12px; color: #949ba4; }
        .footer a { color: #00a8fc; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Discord 連携認証</h2>
        <p style="font-size: 14px; color: #dbdee1;">利用規約を確認し、Captcha を完了して送信してください。</p>
        
        <form action="/verify" method="POST" id="verifyForm">
          <div class="h-captcha" data-sitekey="${siteKey}"></div>

          <label class="checkbox-container">
            <input type="checkbox" id="termsCheck" name="terms_agreed" value="true" required onchange="document.getElementById('submitBtn').disabled = !this.checked;">
            <span><a href="/terms" target="_blank" style="color: #00a8fc;">利用規約</a> と <a href="/privacy" target="_blank" style="color: #00a8fc;">プライバシーポリシー</a> に同意する</span>
          </label>

          <button type="submit" id="submitBtn" disabled>同意して送信</button>
        </form>

        ${adminPanel}

        <div class="footer">
          <a href="/terms" target="_blank">利用規約</a> | <a href="/privacy" target="_blank">プライバシーポリシー</a>
        </div>
      </div>
    </body>
    </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function renderPrivacyPolicy(origin) {
  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>プライバシーポリシー</title>
      <style>
        body { font-family: sans-serif; line-height: 1.6; padding: 20px; max-width: 800px; margin: 0 auto; background: #1e1f22; color: #dbdee1; }
        .container { background: #2b2d31; padding: 30px; border-radius: 8px; }
        h1 { border-bottom: 1px solid #4e5058; padding-bottom: 10px; }
        a { color: #00a8fc; text-decoration: none; }
        a:hover { text-decoration: underline; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>プライバシーポリシー</h1>
        <p>本認証システム（以下「当サービス」）は、ユーザーの個人情報の取扱いについて以下のとおりポリシーを定め、適切に管理します。</p>
        
        <h3>1. 取得する情報</h3>
        <ul>
          <li>Discord アカウント情報（ID、アクセス許可情報）</li>
          <li>接続元情報（IPアドレス、接続種別判定結果）</li>
          <li>識別用 Cookie（サブアカウント検出およびセッション維持用途）</li>
        </ul>

        <h3>2. 利用目的</h3>
        <ul>
          <li>Bot・自動化プログラムによるスパム防止</li>
          <li>VPN/プロキシ等を経由した不正アクセスの判定</li>
          <li>Linked Role（連携ロール）メタデータのDiscordへの送信</li>
          <li>同一端末からの複数サブアカウント制限の判定</li>
        </ul>

        <h3>3. 情報の管理・第三者提供</h3>
        <p>取得した情報は認証・ロール付与に必要な目的以外には使用せず、法令に基づく場合を除き第三者へ開示・提供することはありません。</p>

        <h3>4. データの削除・連携解除</h3>
        <p>ユーザーはいつでも自身の保存データを完全に削除することができます。</p>
        <p>データの削除を希望される場合は、ログインを行った状態で以下の削除専用リンクにアクセスしてください。</p>
        <p style="background: #1e1f22; padding: 10px; border-radius: 4px;">
          データ削除URL: <a href="${origin}/delete-my-data">${origin}/delete-my-data</a>
        </p>
        <p style="font-size: 13px; color: #949ba4;">※ 削除を実行すると、データベースに保存された情報およびDiscord上の連携メタデータがクリアされます。</p>
      </div>
    </body>
    </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function renderTermsOfService() {
  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>利用規約</title>
      <style>
        body { font-family: sans-serif; line-height: 1.6; padding: 20px; max-width: 800px; margin: 0 auto; background: #1e1f22; color: #dbdee1; }
        .container { background: #2b2d31; padding: 30px; border-radius: 8px; }
        h1 { border-bottom: 1px solid #4e5058; padding-bottom: 10px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>利用規約</h1>
        <p>本規約は、当認証システム（以下「当サービス」）の利用条件を定めるものです。利用者は本規約に同意の上、当サービスを利用するものとします。</p>

        <h3>1. 遵守事項</h3>
        <ul>
          <li>利用者は、スパム行為、不正アクセス、セキュリティ検証の迂回を目的とした利用を行ってはなりません。</li>
          <li>複数のサブアカウントを用いて不当に制限を迂回する行為を禁止します。</li>
        </ul>

        <h3>2. サービスの停止・変更</h3>
        <p>当サービスは、保守点検や攻撃への対処などのため、予告なくサービスの提供を一時停止または終了することがあります。</p>

        <h3>3. 免責事項</h3>
        <p>当サービスの利用により発生したいかなる損害についても、運営者は一切の責任を負いません。</p>
      </div>
    </body>
    </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

/* --- Cookie 解析ヘルパー --- */

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;

  cookieHeader.split(";").forEach((cookie) => {
    const parts = cookie.split("=");
    const name = parts.shift()?.trim();
    const value = parts.join("=")?.trim();
    if (name) {
      list[name] = decodeURIComponent(value);
    }
  });

  return list;
}

/* --- 外部API通信 & セキュリティ判定 --- */

async function exchangeCode(code, env) {
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
    return await res.json();
  } catch (e) {
    return null;
  }
}

async function getDiscordUser(accessToken) {
  try {
    const res = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

async function verifyHCaptcha(token, secret) {
  if (!token) return false;
  try {
    const params = new URLSearchParams({ secret, response: token });
    const res = await fetch("https://hcaptcha.com/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString()
    });

    if (!res.ok) return false;
    const data = await res.json();
    return !!data.success;
  } catch (e) {
    return false;
  }
}

function checkIpThreatLevel(request) {
  const cf = request.cf;
  if (!cf || typeof cf !== "object") {
    return true; 
  }

  const country = cf.country || "";
  if (country === "T1" || country === "XX" || cf.botManagement?.isTor || cf.isTor) {
    return true;
  }

  const proxyHeaders = ["via", "x-forwarded-for", "forwarded", "proxy-connection"];
  for (const header of proxyHeaders) {
    if (request.headers.has(header)) {
      const val = request.headers.get(header)?.toLowerCase() || "";
      if (val.includes("proxy") || val.includes("squid") || val.includes("tor")) {
        return true;
      }
    }
  }

  const asn = cf.asn ? Number(cf.asn) : 0;
  const knownVpnAsns = [
    13335, 14061, 16509, 14618, 15169, 8075, 20473, 63949,
    46844, 202425, 60068, 9009, 212238, 39572, 51167, 206216
  ];

  if (knownVpnAsns.includes(asn)) {
    return true;
  }

  const asOrg = (cf.asOrganization || "").toLowerCase();
  const vpnKeywords = [
    "digitalocean", "aws", "amazon", "hostinger", "m247", "linode", "vultr",
    "hetzner", "ovh", "choopa", "google", "azure", "fastly", "cloudflare",
    "nordvpn", "expressvpn", "surfshark", "mullvad", "proton", "cyberghost",
    "private internet access", "datacenter", "hosting", "proxy", "vpn"
  ];

  if (vpnKeywords.some(keyword => asOrg.includes(keyword))) {
    return true;
  }

  return false;
}

async function checkTsukubaVpn(clientIp) {
  if (!clientIp) return true;

  try {
    const requestOptions = {
      headers: { "User-Agent": "Cloudflare-Worker" }
    };

    const res = await fetch("https://www.vpngate.net/api/iphone/", requestOptions);

    if (!res.ok) {
      return true;
    }

    const text = await res.text();
    const lines = text.split("\n");

    for (const line of lines) {
      if (line.startsWith("*") || line.startsWith("#") || !line.trim()) continue;
      const parts = line.split(",");
      if (parts.length > 1 && parts[1] === clientIp) {
        return true;
      }
    }

    return false;
  } catch (e) {
    return true;
  }
}

async function updateRoleConnection(accessToken, metadata, env) {
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
    return false;
  }
}