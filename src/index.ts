const ADMIN_DISCORD_ID = "1506950854249418765";
const SESSION_TTL_SECONDS = 600;
const OAUTH_STATE_TTL_SECONDS = 600;
const MAX_OAUTH_STATES = 5;
const MAX_STORED_OAUTH_STATES = 10000;
const MAX_GUILD_ID_LENGTH = 20;
const MAX_FORM_BODY_BYTES = 64 * 1024;
const MAX_ADMIN_UNLINK_USERS = 100;
const EXTERNAL_REQUEST_TIMEOUT_MS = 10000;

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const cookies = parseCookies(request.headers.get("Cookie") || "");

      // 0-1. プライバシーポリシー
      if (url.pathname === "/privacy") {
        return renderPrivacyPolicy(new URL(env.DISCORD_REDIRECT_URI).origin);
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
      if (url.pathname === "/update-metadata" && request.method === "POST") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `metadata:${getClientIp(request)}`)) {
          return new Response("リクエストが多すぎます。しばらく待ってから再試行してください。", { status: 429 });
        }
        return await handleUpdateMetadata(request, cookies, env);
      }

      // 2. OAuth2 認証開始
      if (url.pathname === "/login") {
        if (!await enforceRateLimit(env.LOGIN_RATE_LIMITER, getClientIp(request))) {
          return new Response("リクエストが多すぎます。しばらく待ってから再試行してください。", { status: 429 });
        }
        const requestedGuildId = url.searchParams.get("guild_id") || "global";
        const guildId = isValidGuildId(requestedGuildId) ? requestedGuildId : "global";
        const stateToken = crypto.randomUUID();

        try {
          await saveOAuthState(env, stateToken, guildId);
        } catch (e) {
          console.error("OAuth state save failed");
          return new Response("認証セッションの保存に失敗しました。", { status: 500 });
        }

        const authUrl = `https://discord.com/oauth2/authorize?client_id=${
          env.DISCORD_CLIENT_ID
        }&redirect_uri=${encodeURIComponent(
          env.DISCORD_REDIRECT_URI
        )}&response_type=code&scope=identify%20role_connections.write&state=${encodeURIComponent(stateToken)}`;

        const headers = new Headers();
        headers.set("Location", authUrl);
        const oauthStates = addOAuthState(cookies["oauth_state"], stateToken);
        headers.append("Set-Cookie", makeOAuthStateCookie(oauthStates));

        return new Response(null, { status: 302, headers });
      }

      // 3. OAuth2 コールバック受取 & 認証画面表示
      if (url.pathname === "/callback") {
        if (!await enforceRateLimit(env.CALLBACK_RATE_LIMITER, getClientIp(request))) {
          return new Response("リクエストが多すぎます。しばらく待ってから再試行してください。", { status: 429 });
        }
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");

        if (!code || !state) {
          return new Response("認証パラメータが不足しています。", { status: 400 });
        }

        if (!/^[0-9a-f-]{36}$/.test(state)) {
          return new Response("無効なセッションまたはCSRFトークンの検証に失敗しました。", { status: 403 });
        }

        const stateResult = await consumeOAuthState(env, state, cookies["oauth_state"]);
        if (!stateResult) {
          return new Response("無効なセッションまたはCSRFトークンの検証に失敗しました。", { status: 403 });
        }
        const { guildId, remainingStates } = stateResult;

        const tokenData = await exchangeCode(code, env);
        if (!tokenData || !tokenData.access_token) {
          return new Response("Discordトークンの取得に失敗しました。", { status: 500 });
        }

        const user = await getDiscordUser(tokenData.access_token);
        if (!user || !user.id) {
          return new Response("Discordユーザー情報の取得に失敗しました。", { status: 500 });
        }

        // サーバーサイドセッション ID 発行
        const sessionId = crypto.randomUUID();
        const sessionPayload = {
          userId: user.id,
          accessToken: await encryptSecret(tokenData.access_token, env.SESSION_ENCRYPTION_KEY),
          refreshToken: await encryptSecret(tokenData.refresh_token || "N/A", env.SESSION_ENCRYPTION_KEY),
          guildId,
          csrfToken: crypto.randomUUID()
        };

        // D1 sessions テーブルに安全に保存
        try {
          await env.DB.prepare(
            `INSERT INTO sessions (session_id, payload, created_at) VALUES (?, ?, ?)`
          ).bind(sessionId, JSON.stringify(sessionPayload), Math.floor(Date.now() / 1000)).run();
        } catch (e) {
          console.error("Session DB Save Error:", e);
          return new Response("セッションの保存に失敗しました。D1データベースの設定を確認してください。", { status: 500 });
        }

        const response = renderAuthPage(user.id, env.HCAPTCHA_SITEKEY, user.id === ADMIN_DISCORD_ID, sessionPayload.csrfToken);
        
        // クライアントには無意味な sessionId のみを割り当てる（トークン漏洩防止）
        response.headers.append(
          "Set-Cookie",
          `v_sess=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`
        );
        response.headers.append("Set-Cookie", makeOAuthStateCookie(remainingStates));

        return response;
      }

      // 4. データ計測 & Discord へメタデータ送信
      if (url.pathname === "/verify" && request.method === "POST") {
        if (!await enforceRateLimit(env.VERIFY_RATE_LIMITER, getClientIp(request))) {
          return new Response("リクエストが多すぎます。しばらく待ってから再試行してください。", { status: 429 });
        }
        const sessionId = cookies["v_sess"];
        if (!sessionId) {
          return new Response("セッションの期限が切れているか無効です。最初からやり直してください。", { status: 401 });
        }

        // DBからセッションデータを取得
        let session = await getSession(env, sessionId);
        if (!session) {
          return new Response("セッションが見つからないか期限切れです。", { status: 401 });
        }

        const formData = await readFormDataWithLimit(request, MAX_FORM_BODY_BYTES);
        if (!formData) {
          return new Response("リクエストが大きすぎます。", { status: 413 });
        }
        const hCaptchaResponse = formData.get("h-captcha-response");
        const termsAgreed = formData.get("terms_agreed");
        const csrfToken = formData.get("csrf_token");
        const clientIp = request.headers.get("cf-connecting-ip") || "";

        if (!termsAgreed || typeof csrfToken !== "string" || csrfToken !== session.csrfToken) {
          return new Response("利用規約およびプライバシーポリシーへの同意が必要です。", { status: 400 });
        }

        // A. hCaptcha 検証
        let humanVerified = 0;
        if (!hCaptchaResponse) {
          return new Response("hCaptchaを完了してください。", { status: 400 });
        }
        
        const isHuman = await verifyHCaptcha(hCaptchaResponse, env.HCAPTCHA_SECRET);
        if (!isHuman) {
          return new Response("Captchaの検証に失敗しました。BOTの可能性があります。", { status: 403 });
        }
        humanVerified = 1;

        // 外部 API と DB を変更する前にセッションを原子的に消費し、並行実行を防ぐ。
        session = await consumeSession(env, sessionId);
        if (!session) {
          return new Response("セッションがすでに使用済みか無効です。", { status: 401 });
        }

        const discordId = session.userId;
        const accessToken = session.accessToken;
        const refreshToken = session.refreshToken || "N/A";
        const guildId = session.guildId;
        const storedAccessToken = await encryptSecret(accessToken, env.SESSION_ENCRYPTION_KEY);
        const storedRefreshToken = await encryptSecret(refreshToken, env.SESSION_ENCRYPTION_KEY);

        // B. IP / VPN / Proxy / Tor / 筑波大学VPN 検証
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

        // C. デバイス識別子の設定・取得
        let deviceId = await verifyDeviceCookie(cookies["device_id"], env.SESSION_SIGNING_KEY);
        if (!deviceId) {
          deviceId = crypto.randomUUID();
        }

        // D. メイン/サブアカウント順位判定ロジック
        let subAccountNumber = 1;
        const nowSeconds = Math.floor(Date.now() / 1000);
        let createdAt = nowSeconds;
        const lockToken = crypto.randomUUID();

        if (!await acquireVerificationLock(env, lockToken, nowSeconds)) {
          return new Response("認証処理が集中しています。しばらく待ってから再試行してください。", { status: 503 });
        }

        try {
          try {
            const existingUserRecord = await env.DB.prepare(
              `SELECT sub_account_number, created_at FROM users WHERE discord_id = ?`
            ).bind(discordId).first();

            if (existingUserRecord) {
              subAccountNumber = Number(existingUserRecord.sub_account_number) || 1;
              createdAt = existingUserRecord.created_at;
            } else {
              const knownDiscordIds = new Set();

              if (deviceId) {
                const deviceMatches = await env.DB.prepare(
                  `SELECT DISTINCT discord_id FROM users WHERE device_id = ? AND discord_id != ?`
                ).bind(deviceId, discordId).all();

                if (deviceMatches?.results) {
                  for (const row of deviceMatches.results) {
                    if (row.discord_id) knownDiscordIds.add(row.discord_id);
                  }
                }
              }

              if (vpnClean === 1 && clientIp) {
                const ipMatches = await env.DB.prepare(
                  `SELECT DISTINCT discord_id FROM users WHERE last_ip = ? AND discord_id != ?`
                ).bind(clientIp, discordId).all();

                if (ipMatches?.results) {
                  for (const row of ipMatches.results) {
                    if (row.discord_id) knownDiscordIds.add(row.discord_id);
                  }
                }
              }

              subAccountNumber = knownDiscordIds.size + 1;
            }

            // 判定と保存を同じロック内で行い、同時検証による番号重複を防ぐ。
            const expiresAt = nowSeconds + 3600;
            await env.DB.prepare(
              `INSERT INTO users (discord_id, guild_id, access_token, refresh_token, expires_at, verified_at, created_at, last_ip, device_id, sub_account_number)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(discord_id, guild_id) DO UPDATE SET
                 access_token = ?, refresh_token = ?, expires_at = ?, verified_at = ?, last_ip = ?, device_id = ?, sub_account_number = ?`
            ).bind(
              discordId, guildId, storedAccessToken, storedRefreshToken, expiresAt, nowSeconds, createdAt, clientIp, deviceId, subAccountNumber,
              storedAccessToken, storedRefreshToken, expiresAt, nowSeconds, clientIp, deviceId, subAccountNumber
            ).run();
          } catch (e) {
            console.error("Database verification error");
            return new Response("データベース処理でエラーが発生しました。", { status: 500 });
          }
        } catch (e) {
          return new Response("認証処理でエラーが発生しました。", { status: 500 });
        } finally {
          await releaseVerificationLock(env, lockToken);
        }

        // F. Discord へメタデータ送信
        const updated = await updateRoleConnection(accessToken, {
          human_verified: Boolean(humanVerified),
          vpn_clean: Boolean(vpnClean),
          sub_account_number: Number(subAccountNumber)
        }, env);

        if (!updated) {
          return new Response("Discord Linked Role メタデータの更新に失敗しました。", { status: 500 });
        }

        const res = new Response(`<html>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px; background: #1e1f22; color: #dbdee1;">
              <h1>このタブを安全に閉じることができます</h1><script>window.close()</script>
            </body>
          </html>`, {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });

        res.headers.append(
          "Set-Cookie",
          `device_id=${await signDeviceCookie(deviceId, env.SESSION_SIGNING_KEY)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`
        );
        res.headers.append("Set-Cookie", "v_sess=; Path=/; HttpOnly; Secure; Max-Age=0");

        return res;
      }

      // 5. 管理者用 全員アンリンク API
      if (url.pathname === "/admin/unlink-all" && request.method === "POST") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `unlink:${getClientIp(request)}`)) {
          return new Response("リクエストが多すぎます。しばらく待ってから再試行してください。", { status: 429 });
        }
        const sessionId = cookies["v_sess"];
        if (!sessionId) {
          return new Response("管理者セッションが見つかりません。先に /login から管理者アカウントでログインしてください。", { status: 401 });
        }

        const session = await getSession(env, sessionId);
        if (!session) {
          return new Response("有効な管理者セッションが存在しません。", { status: 401 });
        }

        if (session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response("アクセス権限がありません。管理者IDのみ実行可能です。", { status: 403 });
        }

        await purgeExpiredUsers(env);
        const { results } = await env.DB.prepare(
          "SELECT discord_id, access_token FROM users WHERE expires_at > ? LIMIT ?"
        ).bind(Math.floor(Date.now() / 1000), MAX_ADMIN_UNLINK_USERS + 1).all();
        if (results && results.length > MAX_ADMIN_UNLINK_USERS) {
          return new Response(`対象ユーザーが多すぎます。一括処理は${MAX_ADMIN_UNLINK_USERS}件までです。`, { status: 413 });
        }
        let successCount = 0;
        let failCount = 0;

        if (results && results.length > 0) {
          for (const user of results) {
            const accessToken = await decryptSecret(user.access_token, env.SESSION_ENCRYPTION_KEY);
            const ok = accessToken ? await updateRoleConnection(accessToken, {}, env) : false;
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

      return Response.redirect(`${new URL(env.DISCORD_REDIRECT_URI).origin}/privacy`, 302);
    } catch (fatalError) {
      console.error("Unhandled request error");
      return new Response("システムエラーが発生しました。", { status: 500 });
    }
  },
  async scheduled(controller, env) {
    await purgeExpiredUsers(env);
  }
};

/* --- ユーザー自身のデータ削除処理 --- */

async function getSession(env, sessionId) {
  if (!sessionId || !/^[0-9a-f-]{36}$/.test(sessionId)) return null;

  try {
    const row = await env.DB.prepare(
      "SELECT payload, created_at FROM sessions WHERE session_id = ?"
    ).bind(sessionId).first();
    if (!row || !row.payload || Number(row.created_at) + SESSION_TTL_SECONDS < Math.floor(Date.now() / 1000)) {
      return null;
    }

    const storedSession = JSON.parse(row.payload);
    const accessToken = await decryptSecret(storedSession.accessToken, env.SESSION_ENCRYPTION_KEY);
    const refreshToken = await decryptSecret(storedSession.refreshToken, env.SESSION_ENCRYPTION_KEY);
    if (!storedSession.userId || !accessToken || !refreshToken || !storedSession.csrfToken) return null;
    return { ...storedSession, accessToken, refreshToken };
  } catch (e) {
    console.error("Session lookup failed");
    return null;
  }
}

async function consumeSession(env, sessionId) {
  if (!sessionId || !/^[0-9a-f-]{36}$/.test(sessionId)) return null;

  try {
    const result = await env.DB.prepare(
      "DELETE FROM sessions WHERE session_id = ? AND created_at >= ? RETURNING payload, created_at"
    ).bind(
      sessionId,
      Math.floor(Date.now() / 1000) - SESSION_TTL_SECONDS
    ).first();
    if (!result?.payload) return null;

    const storedSession = JSON.parse(result.payload);
    const accessToken = await decryptSecret(storedSession.accessToken, env.SESSION_ENCRYPTION_KEY);
    const refreshToken = await decryptSecret(storedSession.refreshToken, env.SESSION_ENCRYPTION_KEY);
    if (!storedSession.userId || !accessToken || !refreshToken || !storedSession.csrfToken) return null;
    return { ...storedSession, accessToken, refreshToken };
  } catch (e) {
    console.error("Session consume failed");
    return null;
  }
}

async function purgeExpiredUsers(env) {
  const { results } = await env.DB.prepare(
    "SELECT discord_id, guild_id, access_token FROM users WHERE expires_at <= ?"
  ).bind(Math.floor(Date.now() / 1000)).all();

  for (const user of results || []) {
    const accessToken = await decryptSecret(user.access_token, env.SESSION_ENCRYPTION_KEY);
    if (!accessToken || !await updateRoleConnection(accessToken, {}, env)) {
      continue;
    }

    await env.DB.prepare(
      "DELETE FROM users WHERE discord_id = ? AND guild_id = ? AND expires_at <= ?"
    ).bind(user.discord_id, user.guild_id, Math.floor(Date.now() / 1000)).run();
  }
}

async function readFormDataWithLimit(request, maxBytes) {
  const contentLength = request.headers.get("Content-Length");
  if (contentLength && Number(contentLength) > maxBytes) return null;
  if (!request.body) return request.formData();

  const reader = request.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch (e) {
    return null;
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new Request(request, { body }).formData();
}

async function saveOAuthState(env, stateToken, guildId) {
  const cutoff = Math.floor(Date.now() / 1000) - OAUTH_STATE_TTL_SECONDS;
  await env.DB.prepare(
    "DELETE FROM sessions WHERE session_id LIKE 'oauth:%' AND created_at < ?"
  ).bind(cutoff).run();
  await env.DB.prepare(
    `DELETE FROM sessions
     WHERE session_id LIKE 'oauth:%'
       AND session_id NOT IN (
         SELECT session_id FROM sessions
         WHERE session_id LIKE 'oauth:%'
         ORDER BY created_at DESC
         LIMIT ?
       )`
  ).bind(MAX_STORED_OAUTH_STATES).run();
  await env.DB.prepare(
    "INSERT INTO sessions (session_id, payload, created_at) VALUES (?, ?, ?)"
  ).bind(
    `oauth:${stateToken}`,
    JSON.stringify({ type: "oauth", guildId }),
    Math.floor(Date.now() / 1000)
  ).run();
}

function parseOAuthStates(value) {
  if (!value) return [];

  try {
    const states = JSON.parse(value);
    if (!Array.isArray(states)) return [];
    return states.filter(state => typeof state === "string" && /^[0-9a-f-]{36}$/.test(state));
  } catch (e) {
    return [];
  }
}

function addOAuthState(value, stateToken) {
  const states = parseOAuthStates(value).filter(state => state !== stateToken);
  states.push(stateToken);
  return states.slice(-MAX_OAUTH_STATES);
}

function makeOAuthStateCookie(states) {
  if (!states.length) {
    return "oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
  }

  return `oauth_state=${encodeURIComponent(JSON.stringify(states))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${OAUTH_STATE_TTL_SECONDS}`;
}

async function consumeOAuthState(env, stateToken, cookieValue) {
  const states = parseOAuthStates(cookieValue);
  if (!states.includes(stateToken)) return null;

  try {
    const remainingStates = states.filter(state => state !== stateToken);
    const result = await env.DB.prepare(
      "DELETE FROM sessions WHERE session_id = ? AND created_at >= ? RETURNING payload, created_at"
    ).bind(
      `oauth:${stateToken}`,
      Math.floor(Date.now() / 1000) - OAUTH_STATE_TTL_SECONDS
    ).first();
    if (!result?.payload) return null;

    const payload = JSON.parse(result.payload);
    if (payload?.type !== "oauth" || !isValidGuildId(payload.guildId)) return null;

    return { guildId: payload.guildId, remainingStates };
  } catch (e) {
    console.error("OAuth state lookup failed");
    return null;
  }
}

function getClientIp(request) {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

async function enforceRateLimit(binding, key) {
  if (!binding || typeof binding.limit !== "function") {
    console.error("RATE_LIMITER binding is not configured");
    return false;
  }

  try {
    const result = await binding.limit({ key });
    return result?.success === true;
  } catch (e) {
    console.error("Rate limit check failed");
    return false;
  }
}

async function acquireVerificationLock(env, lockToken, nowSeconds) {
  try {
    await env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS verification_locks (id INTEGER PRIMARY KEY, lock_token TEXT NOT NULL, locked_until INTEGER NOT NULL)"
    ).run();
    await env.DB.prepare(
      "INSERT OR IGNORE INTO verification_locks (id, lock_token, locked_until) VALUES (1, '', 0)"
    ).run();
    const result = await env.DB.prepare(
      "UPDATE verification_locks SET lock_token = ?, locked_until = ? WHERE id = 1 AND locked_until < ?"
    ).bind(lockToken, nowSeconds + 15, nowSeconds).run();
    return result?.meta?.changes === 1;
  } catch (e) {
    console.error("Verification lock failed");
    return false;
  }
}

async function releaseVerificationLock(env, lockToken) {
  try {
    await env.DB.prepare(
      "UPDATE verification_locks SET lock_token = '', locked_until = 0 WHERE id = 1 AND lock_token = ?"
    ).bind(lockToken).run();
  } catch (e) {
    console.error("Verification lock release failed");
  }
}

function decodeBase64(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function encodeBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function importEncryptionKey(encodedKey) {
  if (!encodedKey || typeof encodedKey !== "string") {
    throw new Error("SESSION_ENCRYPTION_KEY is not configured");
  }

  const keyBytes = decodeBase64(encodedKey.trim());
  if (keyBytes.byteLength !== 32) {
    throw new Error("SESSION_ENCRYPTION_KEY must decode to 32 bytes");
  }

  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function importSigningKey(encodedKey) {
  if (!encodedKey || typeof encodedKey !== "string") {
    throw new Error("SESSION_SIGNING_KEY is not configured");
  }

  const keyBytes = decodeBase64(encodedKey.trim());
  if (keyBytes.byteLength !== 32) {
    throw new Error("SESSION_SIGNING_KEY must decode to 32 bytes");
  }

  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signDeviceCookie(deviceId, encodedKey) {
  const key = await importSigningKey(encodedKey);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(deviceId)
  );
  return `${deviceId}.${encodeBase64(new Uint8Array(signature))}`;
}

async function verifyDeviceCookie(value, encodedKey) {
  if (typeof value !== "string") return null;

  const parts = value.split(".");
  if (parts.length !== 2 || !/^[0-9a-f-]{36}$/.test(parts[0])) return null;

  try {
    const key = await importSigningKey(encodedKey);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      decodeBase64(parts[1]),
      new TextEncoder().encode(parts[0])
    );
    return valid ? parts[0] : null;
  } catch (e) {
    return null;
  }
}

async function encryptSecret(value, encodedKey) {
  const key = await importEncryptionKey(encodedKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(value);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return `enc:v1:${encodeBase64(iv)}.${encodeBase64(new Uint8Array(ciphertext))}`;
}

async function decryptSecret(value, encodedKey) {
  if (typeof value !== "string" || !encodedKey) return null;

  if (!value.startsWith("enc:v1:")) return null;

  try {
    const encoded = value.slice("enc:v1:".length).split(".");
    if (encoded.length !== 2) return null;
    const iv = decodeBase64(encoded[0]);
    const ciphertext = decodeBase64(encoded[1]);
    if (iv.byteLength !== 12 || ciphertext.byteLength < 16) return null;
    const key = await importEncryptionKey(encodedKey);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return new TextDecoder().decode(plaintext);
  } catch (e) {
    return null;
  }
}

function isValidGuildId(guildId) {
  return guildId === "global" || (
    typeof guildId === "string" &&
    guildId.length <= MAX_GUILD_ID_LENGTH &&
    /^\d{17,20}$/.test(guildId)
  );
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function withSecurityHeaders(response, noStore = false) {
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "no-referrer");
  response.headers.set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; script-src 'self' https://js.hcaptcha.com 'unsafe-inline'; frame-src https://*.hcaptcha.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com");
  if (noStore) response.headers.set("Cache-Control", "no-store");
  return response;
}

async function handleDeleteMyData(request, cookies, env) {
  if (request.method !== "GET" && request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, POST" } });
  }

  if (!await enforceRateLimit(env.DELETE_RATE_LIMITER, getClientIp(request))) {
    return new Response("リクエストが多すぎます。しばらく待ってから再試行してください。", { status: 429 });
  }

  const sessionId = cookies["v_sess"];
  if (!sessionId) {
    return new Response(`
      <html>
        <body style="font-family: sans-serif; text-align: center; padding-top: 50px; background: #1e1f22; color: #dbdee1;">
          <h2>認証情報が見つかりません</h2>
          <p>データを削除するには、一度 <a href="/login" style="color: #00a8fc;">ログイン (認証)</a> を行う必要があります。</p>
        </body>
      </html>
    `, { headers: { "Content-Type": "text/html; charset=utf-8" }, status: 401 });
  }

  let session = await getSession(env, sessionId);
  if (!session) {
    return new Response("無効または期限切れのセッションです。", { status: 401 });
  }

  if (request.method === "GET") {
    return withSecurityHeaders(new Response(`
      <!DOCTYPE html><html lang="ja"><meta charset="UTF-8"><title>データ削除確認</title>
      <body><h1>データ削除確認</h1>
      <p>保存された認証データとDiscord連携情報を削除します。この操作は取り消せません。</p>
      <form method="POST" action="/delete-my-data">
        <input type="hidden" name="csrf_token" value="${escapeHtml(session.csrfToken)}">
        <button type="submit">データを削除する</button>
      </form></body></html>
    `, { headers: { "Content-Type": "text/html; charset=utf-8" } }), true);
  }

  const formData = await readFormDataWithLimit(request, MAX_FORM_BODY_BYTES);
  if (!formData) {
    return new Response("リクエストが大きすぎます。", { status: 413 });
  }
  if (formData.get("csrf_token") !== session.csrfToken) {
    return new Response("CSRFトークンの検証に失敗しました。", { status: 403 });
  }

  session = await consumeSession(env, sessionId);
  if (!session) {
    return new Response("セッションがすでに使用済みか無効です。", { status: 401 });
  }

  const roleConnectionCleared = await updateRoleConnection(session.accessToken, {}, env);
  const accessTokenRevoked = await revokeDiscordToken(session.accessToken, env);
  const refreshTokenRevoked = session.refreshToken !== "N/A"
    ? await revokeDiscordToken(session.refreshToken, env)
    : true;

  try {
    await env.DB.prepare("DELETE FROM users WHERE discord_id = ?").bind(session.userId).run();
  } catch (e) {
    return new Response("データベース上のデータ削除に失敗しました。", { status: 500 });
  }

  const res = new Response(`
    <html>
      <body style="font-family: sans-serif; text-align: center; padding-top: 50px; background: #1e1f22; color: #dbdee1;">
        <h1>データ削除完了</h1>
        <p>保存データを削除しました。</p>
        <p>${roleConnectionCleared && accessTokenRevoked && refreshTokenRevoked
          ? "Discord の連携情報と認証トークンも失効させました。"
          : "Discord 側の連携解除または認証トークン失効に失敗しました。管理者へ連絡してください。"}</p>
      </body>
    </html>
  `, { headers: { "Content-Type": "text/html; charset=utf-8" } });

  res.headers.append("Set-Cookie", "v_sess=; Path=/; HttpOnly; Secure; Max-Age=0");
  res.headers.append("Set-Cookie", "device_id=; Path=/; HttpOnly; Secure; Max-Age=0");

  return withSecurityHeaders(res, true);
}

/* --- メタデータ定義更新 --- */

async function handleUpdateMetadata(request, cookies, env) {
  const session = await getSession(env, cookies["v_sess"]);
  if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
    return new Response("管理者権限または有効なCSRFトークンが必要です。", { status: 403 });
  }

  try {
    const url = `https://discord.com/api/v10/applications/${env.DISCORD_CLIENT_ID}/role-connections/metadata`;
    
    const body = [
      {
        key: "human_verified",
        name: "人間認証 (hCaptcha)",
        description: "Captchaを要求する",
        type: 7
      },
      {
        key: "vpn_clean",
        name: "VPN / Proxy / Tor 禁止",
        description: "VPN・Tor・プロキシ・筑波大学公開VPN等を禁止する",
        type: 7
      },
      {
        key: "sub_account_number",
        name: "サブ垢制限",
        description: "許可するアカウント数",
        type: 1
      }
    ];

    const res = await fetchWithTimeout(url, {
      method: "PUT",
      headers: {
        "Authorization": `Bot ${env.DISCORD_BOT_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      await res.text();
      return new Response("メタデータ定義の更新に失敗しました。", { status: 502 });
    }

    return new Response("Discord Linked Role メタデータ定義を更新しました！", { status: 200 });
  } catch (e) {
    return new Response("API通信エラーが発生しました。", { status: 500 });
  }
}

/* --- UI描画 --- */

function renderAuthPage(userId, siteKey, isAdmin = false, csrfToken) {
  const adminPanel = isAdmin ? `
    <div style="margin-top: 25px; padding-top: 15px; border-top: 1px solid #4e5058;">
      <p style="color: #ed4245; font-weight: bold; font-size: 13px;">管理者用メニュー (${ADMIN_DISCORD_ID})</p>
      <button type="button" onclick="unlinkAllUsers()" style="background: #da373c; margin-top: 5px;">⚠️ 全員の連携解除 (全員アンリンク)</button>
    </div>
    <script>
      async function unlinkAllUsers() {
        if (!confirm('本当にデータベース内の全ユーザーの連携（ロールメタデータ）を解除しますか？')) return;
        const res = await fetch('/admin/unlink-all', {
          method: 'POST',
          headers: { 'X-CSRF-Token': '${escapeHtml(csrfToken)}' }
        });
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
          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
          <div class="h-captcha" data-sitekey="${escapeHtml(siteKey)}"></div>

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
  return withSecurityHeaders(new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } }), true);
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
          <li>同一端末および同一IPからの複数サブアカウント制限の判定</li>
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
  return withSecurityHeaders(new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } }), true);
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
  return withSecurityHeaders(new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } }), true);
}

/* --- Cookie 解析ヘルパー --- */

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;

  cookieHeader.split(";").forEach((cookie) => {
    const parts = cookie.split("=");
    const name = parts.shift()?.trim();
    const value = parts.join("=")?.trim();
    if (name && value !== undefined) {
      try {
        list[name] = decodeURIComponent(value);
      } catch (e) {
        list[name] = "";
      }
    }
  });

  return list;
}

/* --- 外部API通信 & セキュリティ判定 --- */

async function fetchWithTimeout(input, init = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), EXTERNAL_REQUEST_TIMEOUT_MS);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function exchangeCode(code, env) {
  try {
    const params = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: env.DISCORD_REDIRECT_URI
    });

    const res = await fetchWithTimeout("https://discord.com/api/v10/oauth2/token", {
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

async function revokeDiscordToken(token, env) {
  if (!token || token === "N/A") return true;

  try {
    const params = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      token
    });
    const res = await fetchWithTimeout("https://discord.com/api/v10/oauth2/token/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString()
    });
    return res.ok;
  } catch (e) {
    return false;
  }
}

async function getDiscordUser(accessToken) {
  try {
    const res = await fetchWithTimeout("https://discord.com/api/v10/users/@me", {
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
    const res = await fetchWithTimeout("https://hcaptcha.com/siteverify", {
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
    return false; // Cloudflare環境外/テスト環境等で誤検出を防ぐ
  }

  const country = cf.country || "";
  if (country === "T1" || country === "XX" || cf.botManagement?.isTor || cf.isTor) {
    return true;
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
    "hetzner", "ovh", "choopa", "azure", "fastly",
    "nordvpn", "expressvpn", "surfshark", "mullvad", "proton", "cyberghost",
    "private internet access", "datacenter", "hosting", "proxy", "vpn"
  ];

  if (vpnKeywords.some(keyword => asOrg.includes(keyword))) {
    return true;
  }

  return false;
}

// 筑波大学 VPN Gate のキャッシュ付チェック
async function checkTsukubaVpn(clientIp) {
  if (!clientIp) return false;

  const cacheUrl = new URL("https://vpngate-cache.internal/list.txt");
  const cache = caches.default;
  let response = await cache.match(cacheUrl);

  if (!response) {
    try {
      response = await fetchWithTimeout("https://www.vpngate.net/api/iphone/", {
        headers: { "User-Agent": "Cloudflare-Worker" }
      });

      if (response.ok) {
        // 5分間キャッシュ
        const responseToCache = new Response(response.body, response);
        responseToCache.headers.set("Cache-Control", "s-maxage=300");
        await cache.put(cacheUrl, responseToCache.clone());
        response = responseToCache;
      } else {
        return false;
      }
    } catch (e) {
      return false;
    }
  }

  try {
    const text = await readResponseTextWithLimit(response, 5 * 1024 * 1024);
    if (text === null) return false;
    return text.includes(`,${clientIp},`);
  } catch (e) {
    return false;
  }
}

async function readResponseTextWithLimit(response, maxBytes) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch (e) {
    return null;
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

async function updateRoleConnection(accessToken, metadata, env) {
  try {
    const url = `https://discord.com/api/v10/users/@me/applications/${env.DISCORD_CLIENT_ID}/role-connection`;
    const body = {
      platform_name: "Verification Service",
      metadata
    };

    const res = await fetchWithTimeout(url, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });

    if (res.status === 200 || res.status === 204) {
      return true;
    }

    console.error(`[Linked Role Error] Status: ${res.status}`);
    return false;
  } catch (e) {
    console.error("[Linked Role Exception]", e);
    return false;
  }
}