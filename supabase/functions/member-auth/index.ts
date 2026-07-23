import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
const INTERNAL_EMAIL_DOMAIN = "members.yori.invalid";
const LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const CODE_CHARS = `${LETTERS}${DIGITS}`;
const encoder = new TextEncoder();

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const allowedOrigins = new Set([
  "https://105-a.github.io",
  "http://localhost:8000",
  "http://127.0.0.1:8000",
]);

type InviteConfig = {
  seed: string;
  rotation_epoch: string;
  interval_days: number;
  grace_hours: number;
};

type SessionUser = {
  id: string;
  email?: string;
};

function corsHeaders(req: Request) {
  const origin = req.headers.get("origin") ?? "";
  return {
    "Access-Control-Allow-Origin": allowedOrigins.has(origin)
      ? origin
      : "https://105-a.github.io",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    Vary: "Origin",
  };
}

function json(req: Request, status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(req), "Content-Type": "application/json; charset=utf-8" },
  });
}

function cleanDisplayName(value: unknown) {
  return String(value ?? "")
    .normalize("NFKC")
    .trim()
    .replace(/\s+/gu, " ");
}

function normalizeLoginName(value: unknown) {
  return cleanDisplayName(value).toLocaleLowerCase("ja-JP");
}

function validDisplayName(value: string) {
  return value.length >= 1 && value.length <= 30 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function validPassword(value: unknown) {
  const password = String(value ?? "");
  return password.length >= 8 && password.length <= 72;
}

function hexToBytes(hex: string) {
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error("Invite seed is invalid");
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < hex.length; index += 2) {
    bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: ArrayBuffer) {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string) {
  return bytesToHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

async function hmac(seed: string, value: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    hexToBytes(seed),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

async function inviteCode(seed: string, period: number) {
  const bytes = await hmac(seed, `yori-calendar-invite:${period}`);
  const chars = [
    LETTERS[bytes[0] % LETTERS.length],
    DIGITS[bytes[1] % DIGITS.length],
    CODE_CHARS[bytes[2] % CODE_CHARS.length],
    CODE_CHARS[bytes[3] % CODE_CHARS.length],
    CODE_CHARS[bytes[4] % CODE_CHARS.length],
  ];
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const swapIndex = bytes[5 + index] % (index + 1);
    [chars[index], chars[swapIndex]] = [chars[swapIndex], chars[index]];
  }
  return chars.join("");
}

async function getInviteState(now = new Date()) {
  const { data, error } = await admin
    .from("invite_config")
    .select("seed,rotation_epoch,interval_days,grace_hours")
    .eq("id", 1)
    .single<InviteConfig>();
  if (error || !data) throw error ?? new Error("Invite configuration is missing");

  const epochMs = new Date(data.rotation_epoch).getTime();
  const intervalMs = Number(data.interval_days) * 86_400_000;
  const elapsedMs = Math.max(0, now.getTime() - epochMs);
  const period = Math.floor(elapsedMs / intervalMs);
  const periodStartMs = epochMs + period * intervalMs;
  const expiresAt = new Date(periodStartMs + intervalMs);
  const graceEndsAt = new Date(periodStartMs + Number(data.grace_hours) * 3_600_000);

  return {
    config: data,
    code: await inviteCode(data.seed, period),
    previousCode: period > 0 && now < graceEndsAt
      ? await inviteCode(data.seed, period - 1)
      : null,
    expiresAt,
  };
}

function clientIp(req: Request) {
  return (
    req.headers.get("cf-connecting-ip") ??
    req.headers.get("x-real-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "unknown"
  );
}

async function attemptKey(req: Request, seed: string, identity: string) {
  return await sha256(`${seed}|${clientIp(req)}|${identity}`);
}

async function assertRateLimit(req: Request, kind: "invite" | "register" | "login", seed: string, identity: string) {
  const key = await attemptKey(req, seed, identity);
  const since = new Date(Date.now() - 15 * 60_000).toISOString();
  const { count, error } = await admin
    .from("auth_attempts")
    .select("id", { count: "exact", head: true })
    .eq("attempt_key", key)
    .eq("attempt_kind", kind)
    .eq("success", false)
    .gte("created_at", since);
  if (error) throw error;
  if ((count ?? 0) >= 5) {
    throw Object.assign(new Error("しばらく待ってから、もう一度お試しください。"), { status: 429 });
  }
  return key;
}

async function recordAttempt(key: string, kind: "invite" | "register" | "login", success: boolean) {
  await admin.from("auth_attempts").insert({ attempt_key: key, attempt_kind: kind, success });
  if (Math.random() < 0.03) {
    await admin.from("auth_attempts").delete().lt("created_at", new Date(Date.now() - 86_400_000).toISOString());
  }
}

async function verifyInvite(req: Request, rawCode: unknown, kind: "invite" | "register") {
  const state = await getInviteState();
  const code = String(rawCode ?? "").trim().toUpperCase();
  const key = await assertRateLimit(req, kind, state.config.seed, code || "empty");
  const valid = /^[A-Z2-9]{5}$/.test(code) && (code === state.code || code === state.previousCode);
  await recordAttempt(key, kind, valid);
  return { valid, expiresAt: state.expiresAt };
}

async function internalEmail(loginName: string) {
  return `member-${await sha256(`yori-member:${loginName}`)}@${INTERNAL_EMAIL_DOMAIN}`;
}

async function internalEmailForLogin(loginName: string) {
  const { data: profile, error: profileError } = await admin
    .from("team_members")
    .select("id")
    .eq("login_name", loginName)
    .maybeSingle();
  if (profileError || !profile) return null;

  const { data, error } = await admin.auth.admin.getUserById(profile.id);
  if (error || !data.user?.email) return null;
  return data.user.email;
}

async function authenticatedUser(req: Request): Promise<SessionUser> {
  const token = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  if (!token) throw Object.assign(new Error("ログインが必要です。"), { status: 401 });
  const { data, error } = await admin.auth.getUser(token);
  if (error || !data.user) throw Object.assign(new Error("ログイン情報を確認できません。"), { status: 401 });
  const { data: profile } = await admin
    .from("team_members")
    .select("id")
    .eq("id", data.user.id)
    .maybeSingle();
  if (!profile) throw Object.assign(new Error("このアカウントは利用できません。"), { status: 403 });
  return data.user;
}

async function createSession(email: string, password: string) {
  const authClient = createClient(SUPABASE_URL, ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data, error } = await authClient.auth.signInWithPassword({ email, password });
  if (error || !data.session) throw error ?? new Error("Session was not created");
  return {
    access_token: data.session.access_token,
    refresh_token: data.session.refresh_token,
  };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(req) });
  if (req.method !== "POST") return json(req, 405, { error: "Method not allowed" });

  try {
    const body = await req.json().catch(() => ({}));
    const action = String(body.action ?? "");

    if (action === "verifyInvite") {
      const result = await verifyInvite(req, body.inviteCode, "invite");
      if (!result.valid) return json(req, 401, { error: "招待コードが違います。" });
      return json(req, 200, { ok: true, expiresAt: result.expiresAt.toISOString() });
    }

    if (action === "register") {
      const displayName = cleanDisplayName(body.displayName);
      const loginName = normalizeLoginName(body.displayName);
      const password = String(body.password ?? "");
      if (!validDisplayName(displayName)) return json(req, 400, { error: "名前は1〜30文字で入力してください。" });
      if (!validPassword(password)) return json(req, 400, { error: "パスワードは8〜72文字で入力してください。" });

      const invite = await verifyInvite(req, body.inviteCode, "register");
      if (!invite.valid) return json(req, 401, { error: "招待コードの有効期限が切れたか、内容が違います。" });

      const email = await internalEmail(loginName);
      const { data: created, error: createError } = await admin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
      });
      if (createError || !created.user) {
        const status = /already|registered|exists/i.test(createError?.message ?? "") ? 409 : 400;
        return json(req, status, { error: status === 409 ? "その名前はすでに使われています。" : "アカウントを作成できませんでした。" });
      }

      const { error: profileError } = await admin.from("team_members").insert({
        id: created.user.id,
        display_name: displayName,
        login_name: loginName,
        created_by: created.user.id,
      });
      if (profileError) {
        await admin.auth.admin.deleteUser(created.user.id);
        const status = profileError.code === "23505" ? 409 : 500;
        return json(req, status, { error: status === 409 ? "その名前はすでに使われています。" : "プロフィールを作成できませんでした。" });
      }

      const session = await createSession(email, password);
      return json(req, 200, { ok: true, session });
    }

    if (action === "login") {
      const loginName = normalizeLoginName(body.displayName);
      const password = String(body.password ?? "");
      if (!validDisplayName(loginName) || !validPassword(password)) {
        return json(req, 401, { error: "名前またはパスワードが違います。" });
      }
      const state = await getInviteState();
      const key = await assertRateLimit(req, "login", state.config.seed, loginName);
      try {
        const email = await internalEmailForLogin(loginName);
        if (!email) throw new Error("Account not found");
        const session = await createSession(email, password);
        await recordAttempt(key, "login", true);
        return json(req, 200, { ok: true, session });
      } catch {
        await recordAttempt(key, "login", false);
        return json(req, 401, { error: "名前またはパスワードが違います。" });
      }
    }

    if (action === "currentInvite") {
      await authenticatedUser(req);
      const state = await getInviteState();
      return json(req, 200, { code: state.code, expiresAt: state.expiresAt.toISOString() });
    }

    if (action === "rename") {
      const user = await authenticatedUser(req);
      const displayName = cleanDisplayName(body.displayName);
      const loginName = normalizeLoginName(body.displayName);
      if (!validDisplayName(displayName)) return json(req, 400, { error: "名前は1〜30文字で入力してください。" });

      const { error: profileError } = await admin
        .from("team_members")
        .update({ display_name: displayName, login_name: loginName, updated_at: new Date().toISOString() })
        .eq("id", user.id);
      if (profileError) {
        return json(req, profileError.code === "23505" ? 409 : 500, {
          error: profileError.code === "23505" ? "その名前はすでに使われています。" : "名前を変更できませんでした。",
        });
      }
      return json(req, 200, { ok: true });
    }

    if (action === "deleteAccount") {
      const user = await authenticatedUser(req);
      const { data: profile, error: profileError } = await admin
        .from("team_members")
        .select("id,display_name,login_name,created_by,created_at,updated_at")
        .eq("id", user.id)
        .single();
      if (profileError || !profile) return json(req, 404, { error: "アカウントが見つかりません。" });

      const { error: removeProfileError } = await admin.from("team_members").delete().eq("id", user.id);
      if (removeProfileError) throw removeProfileError;
      const { error: removeUserError } = await admin.auth.admin.deleteUser(user.id);
      if (removeUserError) {
        await admin.from("team_members").insert(profile);
        throw removeUserError;
      }
      return json(req, 200, { ok: true });
    }

    return json(req, 400, { error: "Unknown action" });
  } catch (error) {
    console.error(error);
    const status = Number((error as { status?: number })?.status) || 500;
    const message = status === 500 ? "処理中にエラーが発生しました。" : String((error as Error)?.message || "処理できませんでした。");
    return json(req, status, { error: message });
  }
});
