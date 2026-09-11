const ADMIN_DISCORD_ID = "1506950854249418765";
const SESSION_TTL_SECONDS = 600;
const OAUTH_STATE_TTL_SECONDS = 600;
const MAX_OAUTH_STATES = 5;
const MAX_STORED_OAUTH_STATES = 10000;
const MAX_GUILD_ID_LENGTH = 20;
const MAX_FORM_BODY_BYTES = 64 * 1024;
const MAX_ADMIN_UNLINK_USERS = 100;
const MAX_ANNOUNCEMENT_LENGTH = 2000;
const WELCOME_MESSAGE = "導入ありがとうございます！お困りの際はこちらにDMをしていただければ対応いたします！";
const DISCORD_ADMINISTRATOR_PERMISSION = 8n;
const DISCORD_INTERACTION_COMMAND = "support";
const DISCORD_INTERACTION_MAX_BODY_BYTES = 64 * 1024;
const EXTERNAL_REQUEST_TIMEOUT_MS = 10000;

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const cookies = parseCookies(request.headers.get("Cookie") || "");

      if (url.pathname === "/discord/interactions" && request.method === "POST") {
        return await handleDiscordInteraction(request, env, ctx);
      }

      // 0-1. プライバシーポリシー
      if (url.pathname === "/privacy") {
        return renderPrivacyPolicy(new URL(env.DISCORD_REDIRECT_URI).origin);
      }

      // 0-2. 利用規約
      if (url.pathname === "/terms") {
        return renderTermsOfService();
      }

      if (url.pathname === "/stats") {
        const stats = await getPublicStats(env);
        return renderPublicStats(stats);
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
          await restoreSession(env, sessionId, session);
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
            await restoreSession(env, sessionId, session);
            return new Response("データベース処理でエラーが発生しました。", { status: 500 });
          }
        } catch (e) {
          await restoreSession(env, sessionId, session);
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
          await restoreSession(env, sessionId, session);
          return new Response("Discord Linked Role メタデータの更新に失敗しました。", { status: 500 });
        }

        const res = new Response(`<html>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px; background: #1e1f22; color: #dbdee1;">
              <h1>認証が完了しました</h1>
              <p>Discord への連携情報を更新しました。このタブは安全に閉じることができます。</p>
            </body>
          </html>`, {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });

        res.headers.append(
          "Set-Cookie",
          `device_id=${await signDeviceCookie(deviceId, env.SESSION_SIGNING_KEY)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`
        );
        res.headers.append("Set-Cookie", "v_sess=; Path=/; HttpOnly; Secure; Max-Age=0");

        return withSecurityHeaders(res, true);
      }

      // 5. 管理者用 認証済みユーザー一覧 API
      if (url.pathname === "/admin/dashboard" && request.method === "GET") {
        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID) {
          return new Response("管理者権限が必要です。", { status: 403 });
        }
        return renderAdminDashboard(session.csrfToken);
      }

      if (url.pathname === "/admin/avatar" && request.method === "GET") {
        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID) {
          return new Response("管理者権限が必要です。", { status: 403 });
        }

        const userId = url.searchParams.get("user_id");
        const guildId = url.searchParams.get("guild_id");
        const avatarHash = url.searchParams.get("avatar");
        const iconHash = url.searchParams.get("icon");
        const isDefaultAvatar = url.searchParams.get("default") === "1";
        const isGuildIcon = Boolean(guildId || iconHash);
        if (isDefaultAvatar && (userId || guildId || avatarHash || iconHash)) {
          return new Response("画像指定が不正です。", { status: 400 });
        }
        if (!isDefaultAvatar && isGuildIcon && (!/^\d{17,20}$/.test(guildId || "") || !/^[a-z\d_-]{8,128}$/i.test(iconHash || ""))) {
          return new Response("画像指定が不正です。", { status: 400 });
        }
        if (!isDefaultAvatar && !isGuildIcon && (!/^\d{17,20}$/.test(userId || "") || !/^[a-z\d_-]{8,128}$/i.test(avatarHash || ""))) {
          return new Response("画像指定が不正です。", { status: 400 });
        }

        const avatarResponse = await fetchWithTimeout(
          isDefaultAvatar
            ? "https://cdn.discordapp.com/embed/avatars/0.png"
            : isGuildIcon
              ? `https://cdn.discordapp.com/icons/${guildId}/${iconHash}.png?size=128`
              : `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.png?size=128`
        );
        if (!avatarResponse.ok) {
          return new Response("プロフィール画像を取得できませんでした。", { status: 404 });
        }

        const response = new Response(avatarResponse.body, {
          headers: {
            "Content-Type": avatarResponse.headers.get("Content-Type") || "image/png",
            "Cache-Control": "private, max-age=300",
            "X-Content-Type-Options": "nosniff"
          }
        });
        return response;
      }

      if (url.pathname === "/admin/dashboard/data" && request.method === "GET") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `dashboard:${getClientIp(request)}`)) {
          return new Response("リクエストが多すぎます。しばらく待ってから再試行してください。", { status: 429 });
        }

        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response(JSON.stringify({ error: "管理者権限または有効なCSRFトークンが必要です。" }), { status: 403 });
        }

        await purgeExpiredUsers(env);
        const { results } = await env.DB.prepare(
          `SELECT discord_id, guild_id, access_token, verified_at, created_at,
                  last_ip, device_id, sub_account_number, expires_at
           FROM users ORDER BY verified_at DESC`
        ).all();
        const users = await Promise.all((results || []).map(async (row) => {
          const accessToken = await decryptSecret(row.access_token, env.SESSION_ENCRYPTION_KEY);
          const profile = accessToken ? await getDiscordUser(accessToken) : null;
          return {
            discord_id: row.discord_id,
            guild_id: row.guild_id,
            verified_at: row.verified_at,
            created_at: row.created_at,
            last_ip: row.last_ip,
            device_id: row.device_id,
            sub_account_number: row.sub_account_number,
            expires_at: row.expires_at,
            display_name: profile?.global_name || profile?.username || "取得失敗",
            username: profile?.username || "",
            avatar_url: profile?.avatar
              ? `/admin/avatar?user_id=${row.discord_id}&avatar=${encodeURIComponent(profile.avatar)}`
              : "/admin/avatar?default=1",
            profile_available: Boolean(profile)
          };
        }));

        return withSecurityHeaders(new Response(JSON.stringify({ users }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        }), true);
      }

      if (url.pathname === "/admin/dashboard/guilds" && request.method === "GET") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `guilds:${getClientIp(request)}`)) {
          return new Response(JSON.stringify({ error: "リクエストが多すぎます。" }), { status: 429 });
        }

        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response(JSON.stringify({ error: "管理者権限または有効なCSRFトークンが必要です。" }), { status: 403 });
        }

        const [{ results }, botGuilds] = await Promise.all([
          env.DB.prepare(
            `SELECT guild_id, COUNT(*) AS verified_count, MAX(verified_at) AS last_verified_at
             FROM users GROUP BY guild_id ORDER BY last_verified_at DESC`
          ).all(),
          getBotGuilds(env)
        ]);
        const counts = new Map((results || []).map(row => [row.guild_id, row]));
        const guilds = botGuilds.map(guild => ({
          id: guild.id,
          name: guild.name || "名前なしサーバー",
          icon_url: guild.icon
            ? `/admin/avatar?guild_id=${guild.id}&icon=${encodeURIComponent(guild.icon)}`
            : "/admin/avatar?default=1",
          member_count: guild.approximate_member_count || null,
          verified_count: Number(counts.get(guild.id)?.verified_count || 0),
          last_verified_at: counts.get(guild.id)?.last_verified_at || null
        }));
        const knownGuildIds = new Set(guilds.map(guild => guild.id));
        for (const row of results || []) {
          if (row.guild_id === "global" || knownGuildIds.has(row.guild_id)) continue;
          guilds.push({
            id: row.guild_id,
            name: "登録データ上のサーバー（Bot APIで未確認）",
            icon_url: "/admin/avatar?default=1",
            member_count: null,
            verified_count: Number(row.verified_count || 0),
            last_verified_at: row.last_verified_at
          });
        }

        return withSecurityHeaders(new Response(JSON.stringify({
          guilds,
          global_verified_count: Number(counts.get("global")?.verified_count || 0)
        }), { headers: { "Content-Type": "application/json; charset=utf-8" } }), true);
      }

      if (url.pathname === "/admin/dashboard/members" && request.method === "GET") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `members:${getClientIp(request)}`)) {
          return new Response(JSON.stringify({ error: "リクエストが多すぎます。" }), { status: 429 });
        }

        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response(JSON.stringify({ error: "管理者権限または有効なCSRFトークンが必要です。" }), { status: 403 });
        }

        const guildId = url.searchParams.get("guild_id");
        if (!/^\d{17,20}$/.test(guildId || "")) {
          return new Response(JSON.stringify({ error: "サーバーIDが不正です。" }), { status: 400 });
        }

        const botGuilds = await getBotGuilds(env);
        if (!botGuilds.some(guild => guild.id === guildId)) {
          return new Response(JSON.stringify({ error: "Botが参加していないサーバーです。" }), { status: 404 });
        }

        const memberResult = await getBotGuildMembers(env, guildId);
        if (!memberResult.ok) {
          return new Response(JSON.stringify({ error: memberResult.error }), { status: memberResult.status });
        }
        return withSecurityHeaders(new Response(JSON.stringify({
          guild_id: guildId,
          members: memberResult.members
        }), { headers: { "Content-Type": "application/json; charset=utf-8" } }), true);
      }

      if (url.pathname === "/admin/announce" && request.method === "POST") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `announce:${getClientIp(request)}`)) {
          return new Response(JSON.stringify({ error: "リクエストが多すぎます。" }), { status: 429 });
        }

        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response(JSON.stringify({ error: "管理者権限または有効なCSRFトークンが必要です。" }), { status: 403 });
        }

        let body;
        try {
          body = await request.json();
        } catch (e) {
          return new Response(JSON.stringify({ error: "リクエスト形式が不正です。" }), { status: 400 });
        }
        if (typeof body?.content !== "string" || !body.content.trim() || body.content.length > MAX_ANNOUNCEMENT_LENGTH) {
          return new Response(JSON.stringify({ error: `本文は1文字以上${MAX_ANNOUNCEMENT_LENGTH}文字以内で入力してください。` }), { status: 400 });
        }

        const result = await announceToAllGuilds(body.content.trim(), env);
        return withSecurityHeaders(new Response(JSON.stringify(result), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        }), true);
      }

      if (url.pathname === "/admin/dm/inbox" && request.method === "GET") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `dm-inbox:${getClientIp(request)}`)) {
          return new Response(JSON.stringify({ error: "リクエストが多すぎます。" }), { status: 429 });
        }
        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response(JSON.stringify({ error: "管理者権限または有効なCSRFトークンが必要です。" }), { status: 403 });
        }
        const inbox = await pollAdminDirectMessages(env);
        return withSecurityHeaders(new Response(JSON.stringify(inbox), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        }), true);
      }

      if (url.pathname === "/admin/dm/reply" && request.method === "POST") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `dm-reply:${getClientIp(request)}`)) {
          return new Response(JSON.stringify({ error: "リクエストが多すぎます。" }), { status: 429 });
        }
        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response(JSON.stringify({ error: "管理者権限または有効なCSRFトークンが必要です。" }), { status: 403 });
        }
        let body;
        try {
          body = await request.json();
        } catch (e) {
          return new Response(JSON.stringify({ error: "リクエスト形式が不正です。" }), { status: 400 });
        }
        if (!/^\d{17,20}$/.test(body?.user_id) || typeof body?.content !== "string" || !body.content.trim() || body.content.length > MAX_ANNOUNCEMENT_LENGTH) {
          return new Response(JSON.stringify({ error: `返信は1文字以上${MAX_ANNOUNCEMENT_LENGTH}文字以内で入力してください。` }), { status: 400 });
        }
        const result = await sendDirectMessage(body.user_id, body.content.trim(), env);
        if (!result.ok) {
          return new Response(JSON.stringify({ error: result.error }), { status: 502 });
        }
        await saveAdminDmMessage(env, result.message_id, body.user_id, body.content.trim(), true);
        return withSecurityHeaders(new Response(JSON.stringify({ ok: true }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        }), true);
      }

      if (url.pathname === "/admin/dm/resolve" && request.method === "POST") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `dm-resolve:${getClientIp(request)}`)) {
          return new Response(JSON.stringify({ error: "リクエストが多すぎます。" }), { status: 429 });
        }
        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response(JSON.stringify({ error: "管理者権限または有効なCSRFトークンが必要です。" }), { status: 403 });
        }
        let body;
        try {
          body = await request.json();
        } catch (e) {
          return new Response(JSON.stringify({ error: "リクエスト形式が不正です。" }), { status: 400 });
        }
        if (!/^\d{17,20}$/.test(body?.user_id)) {
          return new Response(JSON.stringify({ error: "対象ユーザーが不正です。" }), { status: 400 });
        }
        const resolved = body?.resolved !== false;
        await ensureAdminDmTables(env);
        await env.DB.prepare(
          `INSERT INTO admin_dm_channels (user_id, channel_id, last_message_id, resolved_at, updated_at)
           VALUES (?, '', NULL, ?, ?)
           ON CONFLICT(user_id) DO UPDATE SET resolved_at = ?, updated_at = ?`
        ).bind(
          body.user_id, resolved ? Math.floor(Date.now() / 1000) : null, Math.floor(Date.now() / 1000),
          resolved ? Math.floor(Date.now() / 1000) : null, Math.floor(Date.now() / 1000)
        ).run();
        return withSecurityHeaders(new Response(JSON.stringify({ ok: true, resolved }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        }), true);
      }

      if (url.pathname === "/admin/revoke" && request.method === "POST") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `revoke:${getClientIp(request)}`)) {
          return new Response(JSON.stringify({ error: "リクエストが多すぎます。" }), { status: 429 });
        }

        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response(JSON.stringify({ error: "管理者権限または有効なCSRFトークンが必要です。" }), { status: 403 });
        }

        let body;
        try {
          body = await request.json();
        } catch (e) {
          return new Response(JSON.stringify({ error: "リクエスト形式が不正です。" }), { status: 400 });
        }
        if (!/^\d{17,20}$/.test(body?.discord_id) || !isValidGuildId(body?.guild_id)) {
          return new Response(JSON.stringify({ error: "対象ユーザーが不正です。" }), { status: 400 });
        }

        const row = await env.DB.prepare(
          "SELECT access_token, refresh_token FROM users WHERE discord_id = ? AND guild_id = ?"
        ).bind(body.discord_id, body.guild_id).first();
        if (!row) {
          return new Response(JSON.stringify({ error: "対象ユーザーが見つかりません。" }), { status: 404 });
        }

        const accessToken = await decryptSecret(row.access_token, env.SESSION_ENCRYPTION_KEY);
        const refreshToken = await decryptSecret(row.refresh_token, env.SESSION_ENCRYPTION_KEY);
        const roleConnectionCleared = accessToken ? await updateRoleConnection(accessToken, {}, env) : false;
        const accessTokenRevoked = accessToken ? await revokeDiscordToken(accessToken, env) : false;
        const refreshTokenRevoked = refreshToken && refreshToken !== "N/A"
          ? await revokeDiscordToken(refreshToken, env)
          : true;
        await env.DB.prepare("DELETE FROM users WHERE discord_id = ? AND guild_id = ?")
          .bind(body.discord_id, body.guild_id).run();

        return withSecurityHeaders(new Response(JSON.stringify({
          ok: true,
          role_connection_cleared: roleConnectionCleared,
          access_token_revoked: accessTokenRevoked,
          refresh_token_revoked: refreshTokenRevoked
        }), { headers: { "Content-Type": "application/json; charset=utf-8" } }), true);
      }

      if (url.pathname === "/admin/users" && request.method === "GET") {
        if (!await enforceRateLimit(env.ADMIN_RATE_LIMITER, `users:${getClientIp(request)}`)) {
          return new Response("リクエストが多すぎます。しばらく待ってから再試行してください。", { status: 429 });
        }

        const session = await getSession(env, cookies["v_sess"]);
        if (!session || session.userId !== ADMIN_DISCORD_ID || request.headers.get("X-CSRF-Token") !== session.csrfToken) {
          return new Response("管理者権限または有効なCSRFトークンが必要です。", { status: 403 });
        }

        await purgeExpiredUsers(env);
        const { results } = await env.DB.prepare(
          `SELECT discord_id, guild_id, verified_at, created_at, last_ip, device_id,
                  sub_account_number, expires_at
           FROM users
           ORDER BY verified_at DESC`
        ).all();

        return withSecurityHeaders(new Response(JSON.stringify({
          users: results || []
        }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        }), true);
      }

      // 6. 管理者用 全員アンリンク API
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
    await recordPublicStats(env);
    await notifyNewGuilds(env);
    await pollAdminDirectMessages(env);
  }
};

/* --- ユーザー自身のデータ削除処理 --- */

async function handleDiscordInteraction(request, env, ctx) {
  const signature = request.headers.get("X-Signature-Ed25519");
  const timestamp = request.headers.get("X-Signature-Timestamp");
  const publicKey = typeof env.DISCORD_PUBLIC_KEY === "string" ? env.DISCORD_PUBLIC_KEY.trim() : "";
  if (!signature || !timestamp || !publicKey) {
    return new Response("署名検証の設定がありません。", { status: 401 });
  }

  const contentLength = request.headers.get("Content-Length");
  if (contentLength && Number(contentLength) > DISCORD_INTERACTION_MAX_BODY_BYTES) {
    return new Response("リクエストが大きすぎます。", { status: 413 });
  }
  const rawBody = await request.text();
  if (new TextEncoder().encode(rawBody).byteLength > DISCORD_INTERACTION_MAX_BODY_BYTES) {
    return new Response("リクエストが大きすぎます。", { status: 413 });
  }

  if (!await verifyDiscordInteractionSignature(rawBody, signature.trim(), timestamp.trim(), publicKey)) {
    return new Response("署名検証に失敗しました。", { status: 401 });
  }

  let interaction;
  try {
    interaction = JSON.parse(rawBody);
  } catch (e) {
    return new Response("JSONが不正です。", { status: 400 });
  }

  if (interaction?.type === 1) {
    return Response.json({ type: 1 });
  }
  if (interaction?.type !== 2 || interaction.data?.name !== DISCORD_INTERACTION_COMMAND) {
    return Response.json({ type: 4, data: { content: "対応していないインタラクションです。", flags: 64 } });
  }

  const userId = interaction.member?.user?.id || interaction.user?.id;
  const permissions = interaction.member?.permissions;
  let isAdministrator = false;
  try {
    isAdministrator = (BigInt(String(permissions || "0")) & DISCORD_ADMINISTRATOR_PERMISSION) !== 0n;
  } catch (e) {
    isAdministrator = false;
  }
  if (!/^\d{17,20}$/.test(userId || "") || !isAdministrator) {
    return Response.json({ type: 4, data: { content: "サーバー管理者のみ利用できます。", flags: 64 } });
  }

  const content = interaction.data.options?.find(option => option.name === "content")?.value;
  if (typeof content !== "string" || !content.trim() || content.length > MAX_ANNOUNCEMENT_LENGTH) {
    return Response.json({ type: 4, data: { content: `内容は1文字以上${MAX_ANNOUNCEMENT_LENGTH}文字以内で入力してください。`, flags: 64 } });
  }

  await ensureAdminDmTables(env);
  const messageId = `interaction:${interaction.id}`;
  const saved = await saveAdminDmMessage(env, messageId, userId, content.trim(), false);
  if (saved) {
    const notification = sendDirectMessage(ADMIN_DISCORD_ID, `【サーバー管理者から問い合わせ】\n送信者: <@${userId}>\nサーバー: ${interaction.guild_id || "不明"}\n\n${content.trim()}`, env);
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(notification);
  }

  return Response.json({ type: 4, data: { content: "お問い合わせを受け付けました。管理者から DM で返信します。", flags: 64 } });
}

async function verifyDiscordInteractionSignature(body, signature, timestamp, publicKey) {
  try {
    if (!/^[0-9a-f]{128}$/i.test(signature) || !/^[0-9a-f]{64}$/i.test(publicKey) || !/^\d{1,20}$/.test(timestamp)) return false;
    const key = await crypto.subtle.importKey(
      "raw",
      decodeHex(publicKey),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      decodeHex(signature),
      new TextEncoder().encode(timestamp + body)
    );
  } catch (e) {
    console.error("Discord interaction signature verification failed");
    return false;
  }
}

function decodeHex(value) {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

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

async function restoreSession(env, sessionId, session) {
  try {
    const accessToken = await encryptSecret(session.accessToken, env.SESSION_ENCRYPTION_KEY);
    const refreshToken = await encryptSecret(session.refreshToken || "N/A", env.SESSION_ENCRYPTION_KEY);
    await env.DB.prepare(
      "INSERT OR REPLACE INTO sessions (session_id, payload, created_at) VALUES (?, ?, ?)"
    ).bind(
      sessionId,
      JSON.stringify({ ...session, accessToken, refreshToken }),
      Math.floor(Date.now() / 1000)
    ).run();
  } catch (e) {
    console.error("Session restore failed");
  }
}

async function purgeExpiredUsers(env) {
  const { results } = await env.DB.prepare(
    "SELECT discord_id, refresh_token FROM users WHERE expires_at <= ?"
  ).bind(Math.floor(Date.now() / 1000)).all();
  const refreshTokensByUser = new Map();

  for (const user of results || []) {
    if (!refreshTokensByUser.has(user.discord_id)) {
      refreshTokensByUser.set(user.discord_id, user.refresh_token);
    }
  }

  for (const [discordId, storedRefreshToken] of refreshTokensByUser) {
    const refreshToken = await decryptSecret(storedRefreshToken, env.SESSION_ENCRYPTION_KEY);
    if (!refreshToken || refreshToken === "N/A") continue;

    const tokenData = await refreshDiscordToken(refreshToken, env);
    if (!tokenData?.access_token) continue;

    const nextRefreshToken = tokenData.refresh_token || refreshToken;
    const storedAccessToken = await encryptSecret(tokenData.access_token, env.SESSION_ENCRYPTION_KEY);
    const storedNextRefreshToken = await encryptSecret(nextRefreshToken, env.SESSION_ENCRYPTION_KEY);
    const expiresAt = Math.floor(Date.now() / 1000) + (Number(tokenData.expires_in) || 3600);

    await env.DB.prepare(
      `UPDATE users
       SET access_token = ?, refresh_token = ?, expires_at = ?
       WHERE discord_id = ?`
    ).bind(storedAccessToken, storedNextRefreshToken, expiresAt, discordId).run();
  }
}

async function getPublicStats(env) {
  await ensurePublicStatsTable(env);
  const [guilds, userCount] = await Promise.all([
    getBotGuilds(env),
    env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE expires_at > ?")
      .bind(Math.floor(Date.now() / 1000)).first()
  ]);
  const serverCount = Array.isArray(guilds) ? guilds.length : 0;
  const memberCount = (guilds || []).reduce(
    (total, guild) => total + (Number(guild.approximate_member_count) || 0),
    0
  );

  const { results: snapshots } = await env.DB.prepare(
    `SELECT recorded_at, server_count, member_count, verified_user_count
     FROM public_stats_snapshots
     ORDER BY recorded_at DESC LIMIT 168`
  ).all();

  return {
    current: {
      server_count: serverCount,
      member_count: memberCount,
      verified_user_count: Number(userCount?.count || 0)
    },
    snapshots: (snapshots || []).reverse()
  };
}

async function recordPublicStats(env) {
  try {
    await ensurePublicStatsTable(env);

    const stats = await getPublicStatsWithoutHistory(env);
    const recordedAt = Math.floor(Date.now() / 3600000) * 3600;
    await env.DB.prepare(
      `INSERT OR REPLACE INTO public_stats_snapshots
       (recorded_at, server_count, member_count, verified_user_count)
       VALUES (?, ?, ?, ?)`
    ).bind(recordedAt, stats.server_count, stats.member_count, stats.verified_user_count).run();
    await env.DB.prepare(
      "DELETE FROM public_stats_snapshots WHERE recorded_at < ?"
    ).bind(recordedAt - (168 * 3600)).run();
  } catch (e) {
    console.error("Public stats snapshot failed");
  }
}

async function ensurePublicStatsTable(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS public_stats_snapshots (
      recorded_at INTEGER PRIMARY KEY,
      server_count INTEGER NOT NULL,
      member_count INTEGER NOT NULL,
      verified_user_count INTEGER NOT NULL
    )`
  ).run();
}

async function getPublicStatsWithoutHistory(env) {
  const [guilds, userCount] = await Promise.all([
    getBotGuilds(env),
    env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE expires_at > ?")
      .bind(Math.floor(Date.now() / 1000)).first()
  ]);
  return {
    server_count: Array.isArray(guilds) ? guilds.length : 0,
    member_count: (guilds || []).reduce(
      (total, guild) => total + (Number(guild.approximate_member_count) || 0),
      0
    ),
    verified_user_count: Number(userCount?.count || 0)
  };
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
  response.headers.set("Content-Security-Policy", "default-src 'self'; img-src 'self'; frame-ancestors 'none'; script-src 'self' https://js.hcaptcha.com 'unsafe-inline'; frame-src https://*.hcaptcha.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com");
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

function renderAdminDashboard(csrfToken) {
  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>管理者ダッシュボード | Discord 認証</title>
      <style>
        :root { color-scheme: dark; --bg: #0d1117; --panel: #161b22; --panel-2: #1f2630; --line: #303845; --text: #f0f3f6; --muted: #8b98a8; --blue: #58a6ff; --red: #ff6b72; --green: #3fb950; }
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100vh; background: radial-gradient(circle at 10% 0%, #1b2940 0, transparent 32%), var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
        .shell { max-width: 1440px; margin: 0 auto; padding: 36px clamp(18px, 4vw, 56px); }
        .topbar { display: flex; justify-content: space-between; align-items: end; gap: 20px; margin-bottom: 28px; }
        .eyebrow { color: var(--blue); font-size: 12px; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
        h1 { margin: 8px 0 0; font-size: clamp(28px, 4vw, 46px); letter-spacing: -0.03em; }
        .subtle { color: var(--muted); margin: 8px 0 0; }
        .actions { display: flex; gap: 10px; flex-wrap: wrap; justify-content: end; }
        button, input { font: inherit; }
        button { border: 1px solid var(--line); border-radius: 8px; padding: 11px 15px; color: var(--text); background: var(--panel-2); cursor: pointer; font-weight: 700; }
        button:hover { border-color: var(--blue); transform: translateY(-1px); }
        button:disabled { opacity: .6; cursor: wait; transform: none; }
        .danger { background: #3b2028; border-color: #71333c; color: #ffb4b8; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }
        .stat, .content { background: rgba(22, 27, 34, .9); border: 1px solid var(--line); border-radius: 12px; }
        .stat { padding: 18px 20px; }
        .stat-label { color: var(--muted); font-size: 13px; }
        .stat-value { display: block; font-size: 30px; font-weight: 800; margin-top: 5px; }
        .guild-panel { margin-bottom: 20px; padding: 20px; background: rgba(22, 27, 34, .9); border: 1px solid var(--line); border-radius: 12px; }
        .section-heading { display: flex; justify-content: space-between; align-items: end; gap: 12px; margin-bottom: 16px; }
        h2 { margin: 5px 0 0; font-size: 22px; }
        .guild-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 12px; }
        .guild-card { display: flex; align-items: center; gap: 12px; padding: 13px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 10px; }
        .guild-card { cursor: pointer; text-align: left; width: 100%; color: var(--text); }
        .guild-card:hover { border-color: var(--blue); }
        .guild-icon { width: 42px; height: 42px; border-radius: 12px; object-fit: cover; background: var(--bg); flex: 0 0 auto; }
        .guild-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 700; }
        .guild-meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
        .member-panel { display: none; margin-bottom: 20px; padding: 20px; background: rgba(22, 27, 34, .9); border: 1px solid var(--line); border-radius: 12px; }
        .member-panel.open { display: block; }
        .member-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 10px; max-height: 560px; overflow-y: auto; }
        .member-card { display: flex; align-items: center; gap: 10px; padding: 11px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 9px; }
        .member-card .avatar { width: 34px; height: 34px; }
        .announce-panel { margin-bottom: 20px; padding: 20px; background: rgba(22, 27, 34, .9); border: 1px solid var(--line); border-radius: 12px; }
        .announce-form { display: flex; gap: 12px; align-items: end; }
        .announce-form textarea { flex: 1; min-height: 96px; resize: vertical; background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 11px 13px; color: var(--text); outline: none; }
        .announce-form textarea:focus { border-color: var(--blue); }
        .announce-form button { flex: 0 0 auto; }
        .dm-panel { margin-bottom: 20px; padding: 20px; background: rgba(22, 27, 34, .9); border: 1px solid var(--line); border-radius: 12px; }
        .dm-grid { display: grid; grid-template-columns: minmax(220px, .7fr) minmax(320px, 1.3fr); gap: 14px; }
        .dm-users, .dm-thread { min-height: 180px; max-height: 420px; overflow-y: auto; background: var(--bg); border: 1px solid var(--line); border-radius: 8px; }
        .dm-user { display: flex; align-items: center; gap: 10px; width: 100%; padding: 12px; border: 0; border-bottom: 1px solid var(--line); border-radius: 0; text-align: left; }
        .dm-user.selected { border-left: 3px solid var(--blue); background: var(--panel-2); }
        .dm-user-avatar { width: 28px; height: 28px; border-radius: 50%; flex-shrink: 0; object-fit: cover; background: var(--bg); }
        .dm-user-info { min-width: 0; }
        .dm-user-name { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .dm-user-id { display: block; color: var(--muted); font-size: 11px; }
        .dm-message { padding: 10px 12px; border-bottom: 1px solid var(--line); }
        .dm-message.admin { background: rgba(35, 134, 54, .16); }
        .dm-message-meta { color: var(--muted); font-size: 11px; margin-bottom: 4px; }
        .dm-reply { display: flex; gap: 10px; margin-top: 12px; }
        .dm-reply textarea { flex: 1; min-height: 58px; resize: vertical; background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 10px; color: var(--text); }
        .dm-reply #dmResolveButton { background: transparent; border: 1px solid var(--line); white-space: nowrap; }
        .dm-show-resolved { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--muted); margin-bottom: 10px; cursor: pointer; }
        .dm-user.resolved { opacity: .55; }
        .dm-user-resolved-badge { color: var(--muted); font-size: 11px; margin-left: 6px; }
        .content { overflow: hidden; }
        .toolbar { display: flex; gap: 12px; justify-content: space-between; align-items: center; padding: 16px; border-bottom: 1px solid var(--line); }
        .search { width: min(420px, 100%); background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 11px 13px; color: var(--text); outline: none; }
        .search:focus { border-color: var(--blue); }
        .status { color: var(--muted); font-size: 13px; }
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 980px; }
        th, td { padding: 14px 16px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: middle; }
        th { color: var(--muted); font-size: 12px; font-weight: 700; white-space: nowrap; }
        td { font-size: 13px; }
        tr:last-child td { border-bottom: 0; }
        .person { display: flex; align-items: center; gap: 11px; min-width: 190px; }
        .avatar { width: 38px; height: 38px; border-radius: 50%; object-fit: cover; background: var(--panel-2); }
        .name { font-weight: 700; }
        .id, .mono { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11px; }
        .pill { display: inline-block; padding: 4px 8px; border-radius: 999px; background: #193524; color: #7ee787; font-size: 11px; font-weight: 700; }
        .pill.expired { background: #3b2028; color: #ffb4b8; }
        .row-action { padding: 7px 10px; color: #ffb4b8; background: transparent; border-color: #71333c; font-size: 12px; }
        .empty { color: var(--muted); text-align: center; padding: 42px 16px; }
        @media (max-width: 700px) { .topbar { display: block; } .actions { justify-content: start; margin-top: 18px; } .stats { grid-template-columns: 1fr; } .toolbar { display: block; } .search { margin-bottom: 10px; } .section-heading { display: block; } .announce-form { display: block; } .announce-form button { width: 100%; margin-top: 10px; } }
      </style>
    </head>
    <body>
      <main class="shell">
        <header class="topbar">
          <div><div class="eyebrow">Private operations</div><h1>認証ユーザー</h1><p class="subtle">プロフィール、接続情報、認証状態を管理します。</p></div>
          <div class="actions"><button type="button" id="refresh">↻ 更新</button><button type="button" class="danger" id="revokeAll">一括失効（最大100件）</button></div>
        </header>
        <section class="announce-panel"><div class="section-heading"><div><div class="eyebrow">Direct message</div><h2>全サーバー管理者へお知らせ</h2></div><span class="status">所有者・管理者権限のメンバーへ DM 配信</span></div><form class="announce-form" id="announceForm"><textarea id="announcement" maxlength="${MAX_ANNOUNCEMENT_LENGTH}" placeholder="全サーバー管理者に DM する本文" required></textarea><button type="submit" id="announceButton">DMを送信</button></form><p class="status" id="announceStatus"></p></section>
        <section class="dm-panel"><div class="section-heading"><div><div class="eyebrow">Support inbox</div><h2>管理者 DM</h2></div><span class="status" id="dmStatus">受信確認中...</span></div><label class="dm-show-resolved"><input type="checkbox" id="dmShowResolved"> 対応終了済みも表示</label><div class="dm-grid"><div class="dm-users" id="dmUsers"></div><div><div class="dm-thread" id="dmThread"><div class="empty">DMを選択してください。</div></div><form class="dm-reply" id="dmReply"><textarea id="dmReplyContent" maxlength="${MAX_ANNOUNCEMENT_LENGTH}" placeholder="返信内容" required></textarea><button type="submit" id="dmReplyButton">返信</button><button type="button" id="dmResolveButton">対応終了にする</button></form></div></div></section>
        <section class="stats"><div class="stat"><span class="stat-label">登録ユーザー</span><strong class="stat-value" id="total">-</strong></div><div class="stat"><span class="stat-label">有効な認証</span><strong class="stat-value" id="active">-</strong></div><div class="stat"><span class="stat-label">導入サーバー</span><strong class="stat-value" id="guildTotal">-</strong></div><div class="stat"><span class="stat-label">表示中</span><strong class="stat-value" id="visible">-</strong></div></section>
        <section class="guild-panel"><div class="section-heading"><div><div class="eyebrow">Discord installation</div><h2>導入サーバー</h2></div><span class="status" id="guildStatus">読み込み中...</span></div><div class="guild-grid" id="guilds"></div></section>
        <section class="member-panel" id="memberPanel"><div class="section-heading"><div><div class="eyebrow">Server members</div><h2 id="memberTitle">メンバー</h2></div><span class="status" id="memberStatus"></span></div><div class="member-grid" id="members"></div></section>
        <section class="content"><div class="toolbar"><input class="search" id="search" type="search" placeholder="表示名、ユーザーID、IP、Cookie ID を検索"><span class="status" id="status">読み込み中...</span></div><div class="table-wrap"><table><thead><tr><th>ユーザー</th><th>IP アドレス</th><th>Cookie ID</th><th>認証情報</th><th>有効期限</th><th>操作</th></tr></thead><tbody id="rows"></tbody></table><div class="empty" id="empty" hidden>該当するユーザーはいません。</div></div></section>
      </main>
      <script>
        const csrfToken = ${JSON.stringify(String(csrfToken))};
        let users = [];
        const $ = (id) => document.getElementById(id);
        const date = (value) => value ? new Date(value * 1000).toLocaleString('ja-JP') : '-';
        function render() {
          const query = $('search').value.trim().toLowerCase();
          const filtered = users.filter(user => [user.display_name, user.username, user.discord_id, user.last_ip, user.device_id].some(value => String(value || '').toLowerCase().includes(query)));
          $('rows').replaceChildren();
          $('empty').hidden = filtered.length !== 0;
          $('visible').textContent = filtered.length;
          filtered.forEach(user => {
            const row = document.createElement('tr');
            const person = document.createElement('td');
            const personLayout = document.createElement('div'); personLayout.className = 'person';
            const avatar = document.createElement('img'); avatar.className = 'avatar'; avatar.alt = ''; avatar.src = user.avatar_url;
            const personText = document.createElement('div');
            const name = document.createElement('div'); name.className = 'name'; name.textContent = user.display_name;
            const id = document.createElement('div'); id.className = 'id'; id.textContent = user.discord_id;
            personText.append(name, id); personLayout.append(avatar, personText); person.append(personLayout);
            const ip = document.createElement('td'); ip.className = 'mono'; ip.textContent = user.last_ip || '-';
            const cookie = document.createElement('td'); cookie.className = 'mono'; cookie.textContent = user.device_id || '-';
            const verified = document.createElement('td');
            const verifiedPill = document.createElement('span'); verifiedPill.className = 'pill'; verifiedPill.textContent = '認証済み';
            const verifiedDate = document.createElement('div'); verifiedDate.className = 'id'; verifiedDate.textContent = date(user.verified_at);
            verified.append(verifiedPill, verifiedDate);
            const expiry = document.createElement('td'); expiry.textContent = date(user.expires_at);
            const action = document.createElement('td'); const revoke = document.createElement('button'); revoke.className = 'row-action'; revoke.textContent = '失効'; revoke.onclick = () => revokeUser(user, revoke); action.append(revoke);
            row.append(person, ip, cookie, verified, expiry, action); $('rows').append(row);
          });
        }
        async function load() {
          $('status').textContent = '読み込み中...'; $('refresh').disabled = true;
          try { const response = await fetch('/admin/dashboard/data', { headers: { 'X-CSRF-Token': csrfToken } }); const data = await response.json(); if (!response.ok) throw new Error(data.error || '取得に失敗しました'); users = data.users || []; $('total').textContent = users.length; $('active').textContent = users.filter(user => user.expires_at * 1000 > Date.now()).length; render(); $('status').textContent = '最終更新: ' + new Date().toLocaleTimeString('ja-JP'); } catch (error) { $('status').textContent = error.message; } finally { $('refresh').disabled = false; }
        }
        async function loadGuilds() {
          try {
            const response = await fetch('/admin/dashboard/guilds', { headers: { 'X-CSRF-Token': csrfToken } });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'サーバー一覧の取得に失敗しました');
            $('guildTotal').textContent = data.guilds.length;
            $('guildStatus').textContent = '全体認証: ' + data.global_verified_count + '件';
            $('guilds').replaceChildren();
            data.guilds.forEach(guild => {
              const card = document.createElement('article');
              card.className = 'guild-card';
              card.setAttribute('role', 'button');
              card.tabIndex = 0;
              card.onclick = () => loadMembers(guild);
              card.onkeydown = (event) => { if (event.key === 'Enter' || event.key === ' ') loadMembers(guild); };
              const guildIcon = document.createElement('img'); guildIcon.className = 'guild-icon'; guildIcon.alt = ''; guildIcon.src = guild.icon_url;
              const guildText = document.createElement('div');
              const guildName = document.createElement('div'); guildName.className = 'guild-name'; guildName.textContent = guild.name;
              const guildMeta = document.createElement('div'); guildMeta.className = 'guild-meta'; guildMeta.textContent = '認証 ' + guild.verified_count + '件' + (guild.member_count ? ' · メンバー ' + guild.member_count + '人' : '');
              guildText.append(guildName, guildMeta); card.append(guildIcon, guildText);
              $('guilds').append(card);
            });
          } catch (error) {
            $('guildTotal').textContent = '-';
            $('guildStatus').textContent = error.message;
          }
        }
        async function loadMembers(guild) {
          const panel = $('memberPanel');
          panel.classList.add('open');
          $('memberTitle').textContent = guild.name + ' のメンバー';
          $('memberStatus').textContent = '読み込み中...';
          $('members').replaceChildren();
          try {
            const response = await fetch('/admin/dashboard/members?guild_id=' + encodeURIComponent(guild.id), { headers: { 'X-CSRF-Token': csrfToken } });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'メンバー一覧の取得に失敗しました');
            $('memberStatus').textContent = data.members.length + '人';
            data.members.forEach(member => {
              const card = document.createElement('div');
              card.className = 'member-card';
              const memberAvatar = document.createElement('img'); memberAvatar.className = 'avatar'; memberAvatar.alt = ''; memberAvatar.src = member.avatar_url;
              const memberText = document.createElement('div');
              const memberName = document.createElement('div'); memberName.className = 'name'; memberName.textContent = member.display_name + (member.bot ? ' [Bot]' : '');
              const memberId = document.createElement('div'); memberId.className = 'id'; memberId.textContent = member.id;
              memberText.append(memberName, memberId); card.append(memberAvatar, memberText);
              $('members').append(card);
            });
            $('memberPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
          } catch (error) {
            $('memberStatus').textContent = error.message;
          }
        }
        async function revokeUser(user, button) { if (!confirm(user.display_name + ' の認証を失効させますか？')) return; button.disabled = true; try { const response = await fetch('/admin/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ discord_id: user.discord_id, guild_id: user.guild_id }) }); const data = await response.json(); if (!response.ok) throw new Error(data.error || '失効に失敗しました'); users = users.filter(item => !(item.discord_id === user.discord_id && item.guild_id === user.guild_id)); $('total').textContent = users.length; $('active').textContent = users.filter(item => item.expires_at * 1000 > Date.now()).length; render(); } catch (error) { alert(error.message); button.disabled = false; } }
        let dmConversations = [];
        let selectedDmUserId = null;
        function renderDmThread() { const conversation = dmConversations.find(item => item.user_id === selectedDmUserId); $('dmThread').replaceChildren(); $('dmResolveButton').disabled = !conversation; $('dmResolveButton').textContent = conversation?.resolved ? '対応中に戻す' : '対応終了にする'; if (!conversation) { $('dmThread').append(Object.assign(document.createElement('div'), { className: 'empty', textContent: 'DMを選択してください。' })); return; } conversation.messages.forEach(message => { const item = document.createElement('div'); item.className = 'dm-message' + (message.from_admin ? ' admin' : ''); const meta = document.createElement('div'); meta.className = 'dm-message-meta'; meta.textContent = (message.from_admin ? '管理者' : (conversation.username || '相手')) + ' · ' + new Date(message.created_at * 1000).toLocaleString('ja-JP'); const content = document.createElement('div'); content.textContent = message.content; item.append(meta, content); $('dmThread').append(item); }); $('dmThread').scrollTop = $('dmThread').scrollHeight; }
        function renderDmUsers() { $('dmUsers').replaceChildren(); const showResolved = $('dmShowResolved').checked; const visibleConversations = dmConversations.filter(conversation => showResolved || !conversation.resolved); visibleConversations.forEach(conversation => { const button = document.createElement('button'); button.type = 'button'; button.className = 'dm-user' + (conversation.user_id === selectedDmUserId ? ' selected' : '') + (conversation.resolved ? ' resolved' : ''); const avatar = document.createElement('img'); avatar.className = 'dm-user-avatar'; avatar.src = conversation.avatar || '/admin/avatar?default=1'; avatar.alt = ''; const info = document.createElement('div'); info.className = 'dm-user-info'; const name = document.createElement('span'); name.className = 'dm-user-name'; name.textContent = (conversation.username || '不明なユーザー') + (conversation.unread ? ' · 新着' : ''); if (conversation.resolved) { const badge = document.createElement('span'); badge.className = 'dm-user-resolved-badge'; badge.textContent = '対応済み'; name.append(badge); } const id = document.createElement('span'); id.className = 'dm-user-id'; id.textContent = conversation.user_id; info.append(name, id); button.append(avatar, info); button.onclick = () => { selectedDmUserId = conversation.user_id; renderDmUsers(); renderDmThread(); }; $('dmUsers').append(button); }); if (!visibleConversations.length) $('dmUsers').append(Object.assign(document.createElement('div'), { className: 'empty', textContent: dmConversations.length ? '対応終了済みのみです。' : '受信した DM はありません。' })); }
        async function loadDmInbox() { try { const response = await fetch('/admin/dm/inbox', { headers: { 'X-CSRF-Token': csrfToken } }); const data = await response.json(); if (!response.ok) throw new Error(data.error || 'DMの取得に失敗しました'); dmConversations = data.conversations || []; if (!dmConversations.some(item => item.user_id === selectedDmUserId)) selectedDmUserId = dmConversations[0]?.user_id || null; renderDmUsers(); renderDmThread(); $('dmStatus').textContent = '最終確認: ' + new Date().toLocaleTimeString('ja-JP'); } catch (error) { $('dmStatus').textContent = error.message; } }
        $('dmReply').addEventListener('submit', async (event) => { event.preventDefault(); if (!selectedDmUserId) return; const content = $('dmReplyContent').value.trim(); if (!content) return; $('dmReplyButton').disabled = true; try { const response = await fetch('/admin/dm/reply', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ user_id: selectedDmUserId, content }) }); const data = await response.json(); if (!response.ok) throw new Error(data.error || '返信に失敗しました'); $('dmReplyContent').value = ''; await loadDmInbox(); } catch (error) { alert(error.message); } finally { $('dmReplyButton').disabled = false; } });
        $('dmResolveButton').addEventListener('click', async () => { if (!selectedDmUserId) return; const conversation = dmConversations.find(item => item.user_id === selectedDmUserId); const nextResolved = !conversation?.resolved; $('dmResolveButton').disabled = true; try { const response = await fetch('/admin/dm/resolve', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ user_id: selectedDmUserId, resolved: nextResolved }) }); const data = await response.json(); if (!response.ok) throw new Error(data.error || '更新に失敗しました'); await loadDmInbox(); } catch (error) { alert(error.message); } finally { $('dmResolveButton').disabled = false; } });
        $('dmShowResolved').addEventListener('change', renderDmUsers);
        $('announceForm').addEventListener('submit', async (event) => { event.preventDefault(); const content = $('announcement').value.trim(); if (!content || !confirm('全サーバー管理者へ DM を送信しますか？')) return; $('announceButton').disabled = true; $('announceStatus').textContent = '送信中...'; try { const response = await fetch('/admin/announce', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify({ content }) }); const data = await response.json(); if (!response.ok) throw new Error(data.error || 'DM送信に失敗しました'); const failed = data.results.filter(result => !result.ok); $('announceStatus').textContent = '完了: ' + data.sent + 'サーバー成功 / ' + data.total + 'サーバー中' + failed.length + 'サーバー失敗' + (failed.length ? '。詳細はブラウザの開発者コンソールを確認してください。' : ''); if (failed.length) console.warn('DM送信失敗', failed); } catch (error) { $('announceStatus').textContent = error.message; } finally { $('announceButton').disabled = false; } });
        $('search').addEventListener('input', render); $('refresh').addEventListener('click', () => { load(); loadGuilds(); loadDmInbox(); }); $('revokeAll').addEventListener('click', async () => { if (!confirm('有効な認証を最大100件まで失効させ、保存データを削除します。続行しますか？')) return; $('revokeAll').disabled = true; try { const response = await fetch('/admin/unlink-all', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } }); const message = await response.text(); if (!response.ok) throw new Error(message); alert(message); await load(); await loadGuilds(); } catch (error) { alert(error.message); } finally { $('revokeAll').disabled = false; } }); load(); loadGuilds(); loadDmInbox();
      </script>
    </body>
    </html>`;
  return withSecurityHeaders(new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } }), true);
}

function renderAuthPage(userId, siteKey, isAdmin = false, csrfToken) {
  const adminPanel = isAdmin ? `
    <div style="margin-top: 25px; padding-top: 15px; border-top: 1px solid #4e5058;">
      <p style="color: #ed4245; font-weight: bold; font-size: 13px;">管理者用メニュー (${ADMIN_DISCORD_ID})</p>
      <a href="/admin/dashboard" target="_blank" style="display:block; margin-top:5px; padding:12px 20px; background:#238636; color:white; border-radius:4px; font-weight:bold; text-decoration:none;">管理者ダッシュボードを開く</a>
      <button type="button" onclick="unlinkAllUsers()" style="background: #da373c; margin-top: 5px;">⚠️ 全員の連携解除 (全員アンリンク)</button>
      <button type="button" onclick="showUsers()" style="background: #4e5058; margin-top: 5px;">認証済みユーザーを表示</button>
      <pre id="adminUsers" style="display:none; text-align:left; white-space:pre-wrap; max-height:300px; overflow:auto; font-size:12px;"></pre>
    </div>
    <script>
      async function showUsers() {
        const output = document.getElementById('adminUsers');
        const res = await fetch('/admin/users', {
          headers: { 'X-CSRF-Token': ${JSON.stringify(String(csrfToken))} }
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          output.textContent = data.error || 'ユーザー情報の取得に失敗しました。';
          output.style.display = 'block';
          return;
        }
        output.textContent = data.users.map((user, index) => [
          '#' + (index + 1),
          'Discord ID: ' + user.discord_id,
          'Guild: ' + user.guild_id,
          '認証日時: ' + new Date(user.verified_at * 1000).toLocaleString('ja-JP'),
          '作成日時: ' + new Date(user.created_at * 1000).toLocaleString('ja-JP'),
          'IP: ' + user.last_ip,
          '端末ID: ' + user.device_id,
          'サブアカウント番号: ' + user.sub_account_number,
          'トークン有効期限: ' + new Date(user.expires_at * 1000).toLocaleString('ja-JP'),
          '---'
        ].join('\\n')).join('\\n');
        output.style.display = 'block';
      }
      async function unlinkAllUsers() {
        if (!confirm('本当にデータベース内の全ユーザーの連携（ロールメタデータ）を解除しますか？')) return;
        const res = await fetch('/admin/unlink-all', {
          method: 'POST',
          headers: { 'X-CSRF-Token': ${JSON.stringify(String(csrfToken))} }
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
        
        <form action="/verify" method="POST" id="verifyForm" onsubmit="document.getElementById('submitBtn').disabled = true;">
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

function renderPublicStats(stats) {
  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>公開統計 | Discord 認証</title>
      <style>
        :root { color-scheme: dark; --bg: #0c1117; --panel: #161d26; --line: #2b3847; --text: #edf4fb; --muted: #92a1b2; --blue: #61b1ff; --mint: #53d6b1; }
        * { box-sizing: border-box; } body { margin: 0; min-height: 100vh; background: radial-gradient(circle at 85% 0%, #173451 0, transparent 34%), var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
        main { max-width: 1180px; margin: auto; padding: 48px clamp(18px, 5vw, 64px); } .eyebrow { color: var(--blue); font-size: 12px; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; } h1 { margin: 10px 0 8px; font-size: clamp(32px, 6vw, 62px); letter-spacing: -.04em; } .intro { color: var(--muted); margin: 0 0 32px; }
        .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 22px; } .metric, .chart { background: rgba(22, 29, 38, .9); border: 1px solid var(--line); border-radius: 14px; } .metric { padding: 22px; } .metric-label { color: var(--muted); font-size: 13px; } .metric-value { display: block; margin-top: 8px; font-size: clamp(28px, 4vw, 44px); } .chart { padding: 22px; } .chart h2 { margin: 0; font-size: 20px; } .chart-note { color: var(--muted); font-size: 13px; margin: 7px 0 20px; } .chart-area { height: 260px; display: flex; align-items: end; gap: 5px; border-bottom: 1px solid var(--line); padding: 12px 4px 0; overflow: hidden; } .bar-group { height: 100%; min-width: 9px; flex: 1; display: flex; align-items: end; gap: 2px; } .bar { min-height: 3px; border-radius: 3px 3px 0 0; flex: 1; background: var(--blue); } .bar.members { background: var(--mint); } .bar.users { background: #e7bd68; } .legend { display: flex; gap: 16px; color: var(--muted); font-size: 12px; margin-top: 14px; } .legend span::before { content: ''; display: inline-block; width: 8px; height: 8px; border-radius: 2px; background: var(--blue); margin-right: 5px; } .legend .members::before { background: var(--mint); } .legend .users::before { background: #e7bd68; } footer { color: var(--muted); font-size: 12px; margin-top: 20px; }
        @media (max-width: 700px) { .metrics { grid-template-columns: 1fr; } .chart-area { height: 210px; } }
      </style>
    </head>
    <body><main><div class="eyebrow">Open metrics</div><h1>サービスの推移</h1><p class="intro">Discord 認証サービスの公開集計です。個人を特定できる情報は含みません。</p>
      <section class="metrics"><div class="metric"><span class="metric-label">導入サーバー数</span><strong class="metric-value">${stats.current.server_count.toLocaleString("ja-JP")}</strong></div><div class="metric"><span class="metric-label">導入サーバー累計参加人数</span><strong class="metric-value">${stats.current.member_count.toLocaleString("ja-JP")}</strong></div><div class="metric"><span class="metric-label">認証済みユーザー数</span><strong class="metric-value">${stats.current.verified_user_count.toLocaleString("ja-JP")}</strong></div></section>
      <section class="chart"><h2>直近7日間の推移</h2><p class="chart-note">1時間ごとのスナップショット。導入サーバーの参加人数は Discord の概算値です。</p><div class="chart-area" id="chart"></div><div class="legend"><span>サーバー</span><span class="members">参加人数</span><span class="users">認証済み</span></div></section><footer>最終集計: ${new Date().toLocaleString("ja-JP")}</footer></main>
      <script>
        const snapshots = ${JSON.stringify(stats.snapshots)};
        const chart = document.getElementById('chart');
        const max = Math.max(1, ...snapshots.flatMap(item => [item.server_count, item.member_count, item.verified_user_count]));
        snapshots.forEach(item => { const group = document.createElement('div'); group.className = 'bar-group'; [['server_count', ''], ['member_count', ' members'], ['verified_user_count', ' users']].forEach(([key, className]) => { const bar = document.createElement('div'); bar.className = 'bar' + className; bar.style.height = (Number(item[key]) / max * 100) + '%'; bar.title = Number(item[key]).toLocaleString('ja-JP'); group.append(bar); }); chart.append(group); });
      </script>
    </body></html>`;
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
        <p><a href="/stats">公開統計を見る</a></p>
        <p>本認証システム（以下「当サービス」）は、ユーザーの個人情報の取扱いについて以下のとおりポリシーを定め、適切に管理します。</p>
        
        <h3>1. 取得する情報</h3>
        <ul>
          <li>Discord アカウント情報（ID、アクセス許可情報）</li>
          <li>接続元情報（IPアドレス、接続種別判定結果）</li>
          <li>識別用 Cookie（サブアカウント検出およびセッション維持用途）</li>
          <li>Linked Role（連携ロール）メタデータ</li>
          <li>認証日時、認証有効期限</li>
          <li>サブアカウント番号（同一端末および同一IPからの複数アカウント制限判定用途）</li>
          <li>その他、認証・ロール付与に必要な情報</li>
          <li>導入先のサーバー・およびそのメンバー</li>
        </ul>

        <h3>2. 利用目的</h3>
        <ul>
          <li>Bot・自動化プログラムによるスパム防止</li>
          <li>VPN/プロキシ等を経由した不正アクセスの判定</li>
          <li>Linked Role（連携ロール）メタデータのDiscordへの送信</li>
          <li>同一端末および同一IPからの複数サブアカウント制限の判定</li>
          <li>認証済みユーザーの管理</li>
          <li>導入サーバーの管理</li>
          <li>サーバー補強および軽量化などの検討のため</li>
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

// DM同期処理はユーザー数が多いと短時間に大量のDiscord APIリクエストを送るため、
// 429（レート制限）が発生しやすい。何もリトライしないと、レート制限に当たった
// ユーザーだけ「取得失敗→不明なユーザー扱い／受信箱に出ない」という不具合になる。
// Retry-After（またはbody.retry_after）に従って待ってから再試行する。
async function fetchDiscordApiWithRetry(input, init = {}, maxRetries = 3) {
  let response;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    response = await fetchWithTimeout(input, init);
    if (response.status !== 429 || attempt === maxRetries) return response;

    let retryAfterMs = 1000 * (attempt + 1);
    try {
      const header = response.headers.get("Retry-After");
      if (header) {
        retryAfterMs = Math.ceil(parseFloat(header) * 1000);
      } else {
        const body = await response.clone().json();
        if (typeof body?.retry_after === "number") retryAfterMs = Math.ceil(body.retry_after * 1000);
      }
    } catch (e) {
      // ヘッダー/ボディが読めない場合は既定のバックオフ秒数を使う
    }
    await new Promise(resolve => setTimeout(resolve, Math.min(Math.max(retryAfterMs, 250), 5000)));
  }
  return response;
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

async function refreshDiscordToken(refreshToken, env) {
  try {
    const params = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: refreshToken
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

async function getBotGuilds(env) {
  if (!env.DISCORD_BOT_TOKEN) return [];

  try {
    const response = await fetchWithTimeout("https://discord.com/api/v10/users/@me/guilds?with_counts=true", {
      headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` }
    });
    if (!response.ok) return [];
    const guilds = await response.json();
    return Array.isArray(guilds) ? guilds : [];
  } catch (e) {
    console.error("Discord guild lookup failed");
    return [];
  }
}

async function announceToAllGuilds(content, env) {
  await ensureAdminDmTables(env);
  const guilds = await getBotGuilds(env);
  const results = [];

  for (const guild of guilds) {
    const administrators = await getGuildAdministrators(env, guild.id);
    if (!administrators.ok) {
      results.push({ guild_id: guild.id, guild_name: guild.name || "名前なしサーバー", ok: false, error: administrators.error });
      continue;
    }

    const dmResults = [];
    for (const administrator of administrators.members) {
      const result = await sendDirectMessage(administrator.id, content, env);
      dmResults.push(result);
      if (result.ok) {
        await saveAdminDmMessage(env, result.message_id, administrator.id, content, true, null, true);
      }
    }
    const failed = dmResults.filter(result => !result.ok);
    if (dmResults.length === 0) {
      results.push({ guild_id: guild.id, guild_name: guild.name || "名前なしサーバー", ok: false, error: "管理者メンバーを取得できませんでした。" });
      continue;
    }
    results.push({ guild_id: guild.id, guild_name: guild.name || "名前なしサーバー", administrators: administrators.members.length, ok: failed.length === 0, error: failed.length ? "一部の管理者へ DM を送信できませんでした。" : null });
  }

  return {
    total: results.length,
    sent: results.filter(result => result.ok).length,
    results
  };
}

async function notifyNewGuilds(env) {
  await ensureAdminDmTables(env);
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS guild_installations (
      guild_id TEXT PRIMARY KEY,
      guild_name TEXT,
      welcome_sent_at INTEGER
    )`
  ).run();

  const guilds = await getBotGuilds(env);
  for (const guild of guilds) {
    const existing = await env.DB.prepare(
      "SELECT welcome_sent_at FROM guild_installations WHERE guild_id = ?"
    ).bind(guild.id).first();
    if (existing?.welcome_sent_at) continue;

    const administrators = await getGuildAdministrators(env, guild.id);
    if (!administrators.ok || administrators.members.length === 0) continue;

    let sent = 0;
    for (const administrator of administrators.members) {
      const result = await sendDirectMessage(administrator.id, WELCOME_MESSAGE, env);
      if (result.ok) {
        sent++;
        await saveAdminDmMessage(env, result.message_id, administrator.id, WELCOME_MESSAGE, true, null, true);
      }
    }
    if (sent > 0) {
      const now = Math.floor(Date.now() / 1000);
      await env.DB.prepare(
        `INSERT INTO guild_installations (guild_id, guild_name, welcome_sent_at)
         VALUES (?, ?, ?)
         ON CONFLICT(guild_id) DO UPDATE SET guild_name = ?, welcome_sent_at = ?`
      ).bind(guild.id, guild.name || "名前なしサーバー", now, guild.name || "名前なしサーバー", now).run();
    }
  }
}

async function sendDirectMessage(userId, content, env) {
  if (!env.DISCORD_BOT_TOKEN || !/^\d{17,20}$/.test(userId || "")) {
    return { ok: false, error: "DM送信先またはBotトークンが不正です。" };
  }

  try {
    const channelResponse = await fetchDiscordApiWithRetry("https://discord.com/api/v10/users/@me/channels", {
      method: "POST",
      headers: {
        Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ recipient_id: userId })
    });
    if (!channelResponse.ok) {
      return { ok: false, error: channelResponse.status === 403 ? "DMが許可されていません。" : `Discord APIエラー (${channelResponse.status})` };
    }

    const channel = await channelResponse.json();
    const messageResponse = await fetchDiscordApiWithRetry(`https://discord.com/api/v10/channels/${channel.id}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ content })
    });
    if (messageResponse.ok) {
      const message = await messageResponse.json();
      return { ok: true, user_id: userId, message_id: message.id };
    }
    return { ok: false, error: messageResponse.status === 403 ? "DMが許可されていません。" : `Discord APIエラー (${messageResponse.status})` };
  } catch (e) {
    return { ok: false, error: "Discord APIへの接続に失敗しました。" };
  }
}

async function ensureAdminDmTables(env) {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS admin_dm_channels (
      user_id TEXT PRIMARY KEY,
      channel_id TEXT NOT NULL,
      last_message_id TEXT,
      username TEXT,
      avatar TEXT,
      resolved_at INTEGER,
      updated_at INTEGER NOT NULL
    )`
  ).run();
  // 旧バージョンで作成済みのテーブルにも列を追加する（既に存在する場合はエラーを無視）
  try { await env.DB.prepare(`ALTER TABLE admin_dm_channels ADD COLUMN username TEXT`).run(); } catch (e) {}
  try { await env.DB.prepare(`ALTER TABLE admin_dm_channels ADD COLUMN avatar TEXT`).run(); } catch (e) {}
  try { await env.DB.prepare(`ALTER TABLE admin_dm_channels ADD COLUMN resolved_at INTEGER`).run(); } catch (e) {}
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS admin_dm_messages (
      message_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      content TEXT NOT NULL,
      from_admin INTEGER NOT NULL,
      is_broadcast INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    )`
  ).run();
  try { await env.DB.prepare(`ALTER TABLE admin_dm_messages ADD COLUMN is_broadcast INTEGER NOT NULL DEFAULT 0`).run(); } catch (e) {}
}

async function pollAdminDirectMessages(env) {
  await ensureAdminDmTables(env);
  const guilds = await getBotGuilds(env);
  const administratorIds = new Set();
  for (const guild of guilds) {
    const administrators = await getGuildAdministrators(env, guild.id);
    if (!administrators.ok) continue;
    for (const administrator of administrators.members) administratorIds.add(administrator.id);
  }

  for (const userId of administratorIds) {
    if (userId === ADMIN_DISCORD_ID) continue;
    const channel = await getDirectMessageChannel(userId, env);
    if (!channel.ok) continue;
    const cursor = await env.DB.prepare(
      "SELECT last_message_id, username, avatar, resolved_at FROM admin_dm_channels WHERE user_id = ?"
    ).bind(userId).first();
    const isInitialSync = !cursor?.last_message_id;

    // Discord APIは1リクエストにつき最大100件しか返さないため、未同期分が100件を
    // 超えている場合は取りこぼしてしまう。取得件数が100件（＝まだ続きがある可能性）の
    // 間はページングして全件取得する。
    let cursorMessageId = cursor?.last_message_id || null;
    let allMessages = [];
    let pageFailed = false;
    while (true) {
      const page = await getDirectMessages(channel.channel_id, cursorMessageId, env);
      if (!page.ok) { pageFailed = allMessages.length === 0; break; }
      if (page.messages.length === 0) break;
      allMessages = allMessages.concat(page.messages);
      cursorMessageId = page.messages[page.messages.length - 1].id;
      if (page.messages.length < 100) break;
    }
    if (pageFailed) continue;
    const messages = { ok: true, messages: allMessages };

    let shouldReopen = false;
    for (const message of messages.messages) {
      // Bot自身が送信したメッセージ（自動あいさつ・管理者からの返信など）かどうかを判定する。
      // 旧実装は message.author.id === ADMIN_DISCORD_ID で判定していたが、
      // 管理者の返信もBotトークン経由で送られるため常にBot自身が author になり、
      // 実際にはこちらから送っただけのメッセージが「相手からの返信」として扱われていた。
      const isFromBot = message.author?.bot === true;
      await saveAdminDmMessage(env, message.id, userId, message.content || "", isFromBot, message.timestamp);
      if (!isInitialSync && !isFromBot) {
        shouldReopen = true;
        await sendDirectMessage(ADMIN_DISCORD_ID, `【管理者 DM 受信】\n送信者: <@${userId}>\n\n${message.content || "(本文なし)"}`, env);
      }
    }

    // ユーザー名・アバターを未取得の場合のみ取得してキャッシュする
    let username = cursor?.username || null;
    let avatar = cursor?.avatar || null;
    if (!username) {
      const userInfo = await getDiscordUserById(userId, env);
      if (userInfo) {
        username = userInfo.username || username;
        avatar = userInfo.avatar_url || avatar;
      }
    }

    const latestMessageId = messages.messages[messages.messages.length - 1]?.id || cursor?.last_message_id || null;
    const resolvedAt = shouldReopen ? null : (cursor?.resolved_at ?? null);
    await env.DB.prepare(
      `INSERT INTO admin_dm_channels (user_id, channel_id, last_message_id, username, avatar, resolved_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET channel_id = ?, last_message_id = ?, username = ?, avatar = ?, resolved_at = ?, updated_at = ?`
    ).bind(
      userId, channel.channel_id, latestMessageId, username, avatar, resolvedAt, Math.floor(Date.now() / 1000),
      channel.channel_id, latestMessageId, username, avatar, resolvedAt, Math.floor(Date.now() / 1000)
    ).run();
  }

  const { results } = await env.DB.prepare(
    `SELECT m.user_id, m.message_id, m.content, m.from_admin, m.is_broadcast, m.created_at,
            c.username, c.avatar, c.resolved_at
     FROM admin_dm_messages m
     LEFT JOIN admin_dm_channels c ON c.user_id = m.user_id
     ORDER BY m.created_at ASC`
  ).all();
  const conversations = new Map();
  for (const message of results || []) {
    if (!conversations.has(message.user_id)) {
      conversations.set(message.user_id, {
        user_id: message.user_id,
        username: message.username || null,
        avatar: message.avatar || null,
        resolved: Boolean(message.resolved_at),
        has_meaningful_message: false,
        unread: false,
        messages: []
      });
    }
    const conversation = conversations.get(message.user_id);
    // 「相手からの返信」または「管理者が個別に送った返信」がある場合のみ会話として扱う。
    // 一斉送信・参加時の自動あいさつ（is_broadcast=1）だけのスレッドは除外する。
    if (!message.from_admin || !message.is_broadcast) conversation.has_meaningful_message = true;
    conversation.messages.push({
      message_id: message.message_id,
      content: message.content,
      from_admin: Boolean(message.from_admin),
      created_at: message.created_at
    });
  }

  const activeConversations = [...conversations.values()].filter(conversation => conversation.has_meaningful_message);
  return { conversations: activeConversations };
}

async function getDirectMessageChannel(userId, env) {
  try {
    const response = await fetchDiscordApiWithRetry("https://discord.com/api/v10/users/@me/channels", {
      method: "POST",
      headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ recipient_id: userId })
    });
    if (!response.ok) return { ok: false, channel_id: null };
    const channel = await response.json();
    return { ok: Boolean(channel?.id), channel_id: channel?.id || null };
  } catch (e) {
    return { ok: false, channel_id: null };
  }
}

async function getDiscordUserById(userId, env) {
  if (!env.DISCORD_BOT_TOKEN || !/^\d{17,20}$/.test(userId || "")) return null;
  try {
    const response = await fetchDiscordApiWithRetry(`https://discord.com/api/v10/users/${userId}`, {
      headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` }
    });
    if (!response.ok) return null;
    const user = await response.json();
    if (!user?.id) return null;
    // アバターはDiscord CDNへの直リンクではなく、/admin/avatar 経由の自ドメインURLとして返す
    // （フロント側でCDNへ直接アクセスするとContent-Security-Policyでブロックされるため）
    return {
      id: user.id,
      username: user.global_name || user.username || null,
      avatar_url: user.avatar
        ? `/admin/avatar?user_id=${user.id}&avatar=${encodeURIComponent(user.avatar)}`
        : "/admin/avatar?default=1"
    };
  } catch (e) {
    return null;
  }
}

async function getDirectMessages(channelId, after, env) {
  try {
    const query = after ? `?limit=100&after=${encodeURIComponent(after)}` : "?limit=100";
    const response = await fetchDiscordApiWithRetry(`https://discord.com/api/v10/channels/${channelId}/messages${query}`, {
      headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` }
    });
    if (!response.ok) return { ok: false, messages: [] };
    const messages = await response.json();
    if (!Array.isArray(messages)) return { ok: false, messages: [] };
    return { ok: true, messages: messages.reverse() };
  } catch (e) {
    return { ok: false, messages: [] };
  }
}

async function saveAdminDmMessage(env, messageId, userId, content, fromAdmin, timestamp = null, isBroadcast = false) {
  if (!messageId) return false;
  const createdAt = timestamp ? Math.floor(new Date(timestamp).getTime() / 1000) : Math.floor(Date.now() / 1000);
  const result = await env.DB.prepare(
    `INSERT OR IGNORE INTO admin_dm_messages (message_id, user_id, content, from_admin, is_broadcast, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(messageId, userId, content, fromAdmin ? 1 : 0, isBroadcast ? 1 : 0, createdAt).run();
  return result?.meta?.changes === 1;
}

async function getGuildAdministrators(env, guildId) {
  if (!env.DISCORD_BOT_TOKEN || !/^\d{17,20}$/.test(guildId || "")) {
    return { ok: false, error: "サーバーまたはBotトークンが不正です。", members: [] };
  }

  try {
    const guildResponse = await fetchWithTimeout(`https://discord.com/api/v10/guilds/${guildId}`, {
      headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` }
    });
    if (!guildResponse.ok) {
      return { ok: false, error: guildResponse.status === 403 ? "Botにサーバー情報の閲覧権限がありません。" : `Discord APIエラー (${guildResponse.status})`, members: [] };
    }
    const guild = await guildResponse.json();
    const administrators = new Map();
    if (/^\d{17,20}$/.test(guild.owner_id || "")) administrators.set(guild.owner_id, { id: guild.owner_id });

    const rolesResponse = await fetchWithTimeout(`https://discord.com/api/v10/guilds/${guildId}/roles`, {
      headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` }
    });
    if (!rolesResponse.ok) {
      return { ok: false, error: rolesResponse.status === 403 ? "Botにロール情報の閲覧権限がありません。" : `Discord APIエラー (${rolesResponse.status})`, members: [] };
    }
    const roles = await rolesResponse.json();
    if (!Array.isArray(roles)) return { ok: false, error: "Discordのロール情報が不正です。", members: [] };
    const administratorRoleIds = new Set();
    for (const role of roles) {
      try {
        if ((BigInt(String(role.permissions || "0")) & DISCORD_ADMINISTRATOR_PERMISSION) !== 0n) {
          administratorRoleIds.add(role.id);
        }
      } catch (e) {
        continue;
      }
    }

    let after = "0";
    while (true) {
      const response = await fetchWithTimeout(`https://discord.com/api/v10/guilds/${guildId}/members?limit=1000&after=${after}`, {
        headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` }
      });
      if (!response.ok) {
        return { ok: false, error: response.status === 403 ? "Botにメンバー情報の閲覧権限がありません。" : `Discord APIエラー (${response.status})`, members: [] };
      }
      const members = await response.json();
      if (!Array.isArray(members)) return { ok: false, error: "Discordのメンバー情報が不正です。", members: [] };
      for (const member of members) {
        const userId = member.user?.id;
        if (!userId) continue;
        let isAdministrator = false;
        try {
          isAdministrator = (BigInt(String(member.permissions || "0")) & DISCORD_ADMINISTRATOR_PERMISSION) !== 0n;
        } catch (e) {
          isAdministrator = false;
        }
        if (!isAdministrator && Array.isArray(member.roles)) {
          isAdministrator = member.roles.some(roleId => administratorRoleIds.has(roleId));
        }
        if (isAdministrator) administrators.set(userId, { id: userId });
      }
      if (members.length < 1000) break;
      const lastId = members[members.length - 1]?.user?.id;
      if (!lastId || lastId === after) break;
      after = lastId;
    }

    return { ok: true, error: null, members: [...administrators.values()] };
  } catch (e) {
    return { ok: false, error: "Discord APIへの接続に失敗しました。", members: [] };
  }
}

function compareDiscordChannels(left, right) {
  const positionDifference = Number(left.position || 0) - Number(right.position || 0);
  return positionDifference || String(left.id).localeCompare(String(right.id));
}

async function getBotGuildChannels(env, guildId) {
  if (!env.DISCORD_BOT_TOKEN) {
    return { ok: false, error: "Botトークンが設定されていません。", channels: [] };
  }

  try {
    const response = await fetchWithTimeout(`https://discord.com/api/v10/guilds/${guildId}/channels`, {
      headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` }
    });
    if (!response.ok) {
      return {
        ok: false,
        error: response.status === 403 ? "Botにチャンネル閲覧権限がありません。" : `Discord APIエラー (${response.status})`,
        channels: []
      };
    }
    const channels = await response.json();
    return { ok: Array.isArray(channels), error: Array.isArray(channels) ? null : "Discordのチャンネル情報が不正です。", channels: Array.isArray(channels) ? channels : [] };
  } catch (e) {
    return { ok: false, error: "Discord APIへの接続に失敗しました。", channels: [] };
  }
}

async function getBotGuildMembers(env, guildId) {
  if (!env.DISCORD_BOT_TOKEN) {
    return { ok: false, status: 503, error: "Botトークンが設定されていません。", members: [] };
  }

  try {
    const response = await fetchWithTimeout(
      `https://discord.com/api/v10/guilds/${guildId}/members?limit=1000`,
      { headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` } }
    );
    if (!response.ok) {
      return {
        ok: false,
        status: response.status === 403 ? 403 : response.status === 429 ? 429 : 502,
        error: response.status === 403
          ? "Botにメンバー閲覧権限がありません。"
          : response.status === 429
            ? "Discord APIのレート制限中です。しばらく待ってください。"
            : "Discordからメンバー情報を取得できませんでした。",
        members: []
      };
    }
    const members = await response.json();
    if (!Array.isArray(members)) {
      return { ok: false, status: 502, error: "Discordのメンバー情報が不正です。", members: [] };
    }

    return { ok: true, status: 200, error: null, members: members.map(member => ({
      id: member.user?.id,
      username: member.user?.username || "不明なユーザー",
      display_name: member.nick || member.user?.global_name || member.user?.username || "不明なユーザー",
      avatar_url: member.user?.avatar
        ? `/admin/avatar?user_id=${member.user.id}&avatar=${encodeURIComponent(member.user.avatar)}`
        : "/admin/avatar?default=1",
      joined_at: member.joined_at || null,
      bot: Boolean(member.user?.bot)
    })).filter(member => member.id) };
  } catch (e) {
    console.error("Discord guild member lookup failed");
    return { ok: false, status: 502, error: "Discord APIへの接続に失敗しました。", members: [] };
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
