const projectUrl = Deno.env.get("SUPABASE_URL");
const publishableKey = Deno.env.get("SUPABASE_KEY");
const inviteCode = Deno.env.get("INVITE_CODE");

if (!projectUrl || !publishableKey || !inviteCode) {
  throw new Error("SUPABASE_URL, SUPABASE_KEY and INVITE_CODE are required");
}

const suffix = Date.now().toString(36);
const originalName = `Codex確認${suffix}`;
const renamedName = `${originalName}改`;
const password = `Yori-${crypto.randomUUID()}!`;
let activeToken = "";

async function call(action: string, body: Record<string, unknown> = {}, token = "") {
  const response = await fetch(`${projectUrl}/functions/v1/member-auth`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: publishableKey,
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ action, ...body }),
  });
  const data = await response.json().catch(() => ({}));
  return { response, data };
}

function jwtSubject(token: string) {
  const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(payload)).sub as string;
}

async function rest(path: string, token: string) {
  const response = await fetch(`${projectUrl}/rest/v1/${path}`, {
    headers: { apikey: publishableKey, Authorization: `Bearer ${token}` },
  });
  return { status: response.status, data: await response.json().catch(() => null) };
}

try {
  const invite = await call("verifyInvite", { inviteCode });
  if (!invite.response.ok) throw new Error(`Invite verification failed: ${JSON.stringify(invite.data)}`);

  const registration = await call("register", { displayName: originalName, password, inviteCode });
  if (!registration.response.ok) throw new Error(`Registration failed: ${JSON.stringify(registration.data)}`);
  activeToken = registration.data.session.access_token;
  const registeredId = jwtSubject(activeToken);

  const login = await call("login", { displayName: originalName, password });
  if (!login.response.ok) throw new Error(`Login failed: ${JSON.stringify(login.data)}`);
  if (jwtSubject(login.data.session.access_token) !== registeredId) throw new Error("Login returned a different account");

  const [events, members, currentInvite] = await Promise.all([
    rest("calendar_events?select=id", login.data.session.access_token),
    rest("team_members?select=id,display_name", login.data.session.access_token),
    call("currentInvite", {}, login.data.session.access_token),
  ]);
  if (events.status !== 200 || !Array.isArray(events.data)) throw new Error("Calendar RLS read failed");
  if (members.status !== 200 || !members.data.some((member: { id: string }) => member.id === registeredId)) throw new Error("Member RLS read failed");
  if (!currentInvite.response.ok || currentInvite.data.code !== inviteCode) throw new Error("Current invite lookup failed");

  const rename = await call("rename", { displayName: renamedName }, login.data.session.access_token);
  if (!rename.response.ok) throw new Error(`Rename failed: ${JSON.stringify(rename.data)}`);

  const renamedLogin = await call("login", { displayName: renamedName, password });
  if (!renamedLogin.response.ok) throw new Error(`Renamed login failed: ${JSON.stringify(renamedLogin.data)}`);
  activeToken = renamedLogin.data.session.access_token;
  if (jwtSubject(activeToken) !== registeredId) throw new Error("Rename changed the account ID");

  const deletion = await call("deleteAccount", {}, activeToken);
  if (!deletion.response.ok) throw new Error(`Deletion failed: ${JSON.stringify(deletion.data)}`);

  const afterDeletion = await rest("calendar_events?select=id", activeToken);
  if (afterDeletion.status !== 200 || !Array.isArray(afterDeletion.data) || afterDeletion.data.length !== 0) {
    throw new Error("Deleted account retained calendar access");
  }

  const deletedLogin = await call("login", { displayName: renamedName, password });
  if (deletedLogin.response.ok) throw new Error("Deleted account can still log in");

  console.log(JSON.stringify({
    invite: "ok",
    register: "ok",
    sameAccountLogin: "ok",
    calendarRls: "ok",
    memberRls: "ok",
    rename: "ok",
    delete: "ok",
    revokedAfterDelete: "ok",
  }));
  activeToken = "";
} finally {
  if (activeToken) await call("deleteAccount", {}, activeToken).catch(() => undefined);
}
