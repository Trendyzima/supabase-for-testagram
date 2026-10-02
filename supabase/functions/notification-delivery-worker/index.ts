import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.51.0";
import { SignJWT, importPKCS8 } from "npm:jose@6.2.12";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://testagram.site",
  "Access-Control-Allow-Headers": "content-type, x-notification-worker-token",
  "Content-Type": "application/json",
};
const json = (status: number, body: Record<string, unknown>) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

type ServiceAccount = { project_id: string; client_email: string; private_key: string };

function safeUrl(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) return "https://testagram.site/notifications";
  try {
    const u = new URL(value);
    if (u.protocol === "https:" && (u.hostname === "testagram.site" || u.hostname === "www.testagram.site")) return u.toString();
  } catch {}
  return "https://testagram.site/notifications";
}

function copyFor(kind: string, actor: string, data: Record<string, unknown>) {
  const name = actor || "Someone";
  const title = typeof data.title === "string" ? data.title.slice(0, 120) : "";
  const body = typeof data.body === "string" ? data.body.slice(0, 240) : "";
  if (title && body) return { title, body };
  const map: Record<string, {title: string; body: string}> = {
    like: {title: "New like", body: name + " liked your post."},
    repost: {title: "New repost", body: name + " reposted your post."},
    reply: {title: "New reply", body: name + " replied to your post."},
    quote: {title: "New quote", body: name + " quoted your post."},
    follow: {title: "New follower", body: name + " followed you."},
    mention: {title: "You were mentioned", body: name + " mentioned you."},
    verified: {title: "Testagram", body: "Your account has a new notification."},
    test_push: {title: "Testagram notifications", body: "Push notifications are working on this device."},
  };
  return map[kind] || {title: "Testagram", body: "You have a new notification."};
}

async function secret(admin: ReturnType<typeof createClient>, name: string): Promise<string | null> {
  const {data, error} = await admin.rpc("get_notification_secret", {p_name: name});
  if (error) { console.error("[notification-worker] secret lookup failed:", error.message); return null; }
  return typeof data === "string" ? data : null;
}

async function mintJwt(sa: ServiceAccount): Promise<string> {
  const key = await importPKCS8(sa.private_key, "RS256");
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({scope: "https://www.googleapis.com/auth/firebase.messaging"})
    .setProtectedHeader({alg: "RS256", typ: "JWT"})
    .setIssuer(sa.client_email)
    .setSubject(sa.client_email)
    .setAudience("https://oauth2.googleapis.com/token")
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(key);
}

async function accessToken(sa: ServiceAccount): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: await mintJwt(sa),
  });
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body,
  });
  if (!res.ok) throw new Error("google_oauth_" + res.status);
  const data = await res.json();
  if (typeof data.access_token !== "string") throw new Error("google_oauth_missing_access_token");
  return data.access_token;
}

async function sendFcm(sa: ServiceAccount, bearer: string, token: string, title: string, body: string, data: Record<string,string>): Promise<"sent"|"invalid"> {
  const res = await fetch("https://fcm.googleapis.com/v1/projects/" + encodeURIComponent(sa.project_id) + "/messages:send", {
    method: "POST",
    headers: {Authorization: "Bearer " + bearer, "Content-Type": "application/json"},
    body: JSON.stringify({
      message: {
        token,
        notification: {title, body},
        data,
        android: {
          priority: "high",
          ttl: "2419200s",
          restricted_package_name: "com.xclone.app",
          notification: {channel_id: "testagram_notifications", default_sound: true, notification_priority: "high"},
        },
      },
    }),
  });
  if (res.ok) return "sent";
  const raw = await res.text();
  let status = "";
  let fcmCode = "";
  try {
    const parsed = JSON.parse(raw);
    status = parsed?.error?.status || "";
    const details = Array.isArray(parsed?.error?.details) ? parsed.error.details : [];
    const detail = details.find((d: Record<string,unknown>) => String(d["@type"] || "").includes("google.firebase.fcm.v1.FcmError"));
    fcmCode = typeof detail?.errorCode === "string" ? detail.errorCode : "";
  } catch {}
  if (res.status === 404 || fcmCode === "UNREGISTERED") return "invalid";
  if (res.status === 429 || res.status >= 500 || res.status === 401 || res.status === 403) throw new Error("fcm_transient_" + res.status);
  if (fcmCode === "INVALID_ARGUMENT" && status === "INVALID_ARGUMENT") return "invalid";
  throw new Error("fcm_rejected_" + res.status);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", {headers: corsHeaders});
  if (req.method !== "POST") return json(405, {error: "method_not_allowed"});

  const url = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceRoleKey) return json(500, {error: "server_not_configured"});

  const admin = createClient(url, serviceRoleKey, {auth: {persistSession: false, autoRefreshToken: false}});
  const expected = await secret(admin, "notification_worker_token");
  const supplied = req.headers.get("x-notification-worker-token");
  if (!expected || !supplied || supplied !== expected) return json(401, {error: "unauthorized"});

  const rawServiceAccount = Deno.env.get("FCM_SERVICE_ACCOUNT_JSON") || await secret(admin, "fcm_service_account_json");
  if (!rawServiceAccount) return json(503, {error: "fcm_not_configured"});

  let sa: ServiceAccount;
  try {
    sa = JSON.parse(rawServiceAccount);
    if (!sa.project_id || !sa.client_email || !sa.private_key) throw new Error("invalid_service_account");
  } catch {
    return json(500, {error: "invalid_fcm_service_account"});
  }

  let bearer: string;
  try { bearer = await accessToken(sa); }
  catch (e) { console.error("[notification-worker] FCM auth failed", e); return json(502, {error: "fcm_auth_failed"}); }

  const {data: batch, error: claimError} = await admin.rpc("claim_notification_delivery_batch", {p_limit: 20});
  if (claimError) return json(500, {error: "claim_failed"});

  let sent = 0, retried = 0, skipped = 0, invalidTokens = 0;

  for (const item of batch || []) {
    try {
      const {data: prefs} = await admin.from("notification_preferences").select("push_enabled").eq("user_id", item.recipient_id).maybeSingle();
      if (prefs?.push_enabled === false) {
        await admin.rpc("complete_notification_delivery", {p_id: item.id});
        skipped++;
        continue;
      }

      const {data: tokens, error: tokenError} = await admin.from("app_push_tokens")
        .select("id,token").eq("user_id", item.recipient_id).eq("provider", "fcm").eq("platform", "android").eq("enabled", true);
      if (tokenError) throw new Error("token_lookup:" + tokenError.message);
      if (!tokens?.length) {
        await admin.rpc("complete_notification_delivery", {p_id: item.id});
        skipped++;
        continue;
      }

      const payload = (item.payload || {}) as Record<string,unknown>;
      const nested = (payload.data || {}) as Record<string,unknown>;
      const kind = String(payload.kind || item.event_name || "notification");
      const actorId = typeof payload.actor_id === "string" ? payload.actor_id : null;
      let actor = "Someone";
      if (actorId) {
        const {data: profile} = await admin.from("profiles").select("username,display_name").eq("id", actorId).maybeSingle();
        actor = profile?.display_name || profile?.username || actor;
      }

      const copy = copyFor(kind, actor, nested);
      const fcmData = {
        notification_id: String(payload.notification_id || item.notification_id),
        type: kind,
        url: safeUrl(nested.action_url || nested.url),
      };
      let retry = false;

      for (const tokenRow of tokens) {
        const {data: existing} = await admin.from("notification_push_deliveries")
          .select("id,status,attempts")
          .eq("notification_id", item.notification_id).eq("push_token_id", tokenRow.id).maybeSingle();
        if (existing?.status === "sent") continue;

        const now = new Date().toISOString();
        const attempts = (existing?.attempts || 0) + 1;
        const {data: delivery, error: stateError} = await admin.from("notification_push_deliveries")
          .upsert({
            id: existing?.id,
            notification_id: item.notification_id,
            push_token_id: tokenRow.id,
            provider: "fcm",
            status: "processing",
            attempts,
            last_error: null,
            updated_at: now,
          }, {onConflict: "notification_id,push_token_id"}).select("id").single();
        if (stateError) throw new Error("delivery_state:" + stateError.message);

        try {
          const result = await sendFcm(sa, bearer, tokenRow.token, copy.title, copy.body, fcmData);
          if (result === "invalid") {
            await admin.from("app_push_tokens").delete().eq("id", tokenRow.id);
            await admin.from("notification_push_deliveries").update({
              status: "sent", sent_at: now, updated_at: now, last_error: "FCM token invalid",
            }).eq("id", delivery.id);
            invalidTokens++;
          } else {
            await admin.from("notification_push_deliveries").update({
              status: "sent", sent_at: now, updated_at: now, last_error: null,
            }).eq("id", delivery.id);
            sent++;
          }
        } catch (e) {
          retry = true;
          const message = e instanceof Error ? e.message : "fcm_delivery_failed";
          await admin.from("notification_push_deliveries").update({
            status: "failed",
            last_error: message.slice(0, 500),
            next_attempt_at: new Date(Date.now() + 15000).toISOString(),
            updated_at: now,
          }).eq("id", delivery.id);
          retried++;
        }
      }

      if (retry) await admin.rpc("fail_notification_delivery", {p_id: item.id, p_error: "One or more FCM deliveries need retry."});
      else await admin.rpc("complete_notification_delivery", {p_id: item.id});
    } catch (e) {
      const message = e instanceof Error ? e.message : "notification_delivery_failed";
      await admin.rpc("fail_notification_delivery", {p_id: item.id, p_error: message});
      retried++;
    }
  }

  return json(200, {ok: true, claimed: batch?.length || 0, sent, retried, skipped, invalidTokens});
});
