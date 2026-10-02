import { createClient } from "https://esm.sh/@supabase/supabase-js@2.51.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://testagram.site",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders,
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return json(405, { error: "method_not_allowed" });
  }

  const authorization = req.headers.get("Authorization");
  const accessToken = authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!accessToken) {
    return json(401, { error: "missing_authorization" });
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const publishableKeys = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS");
  let supabasePublishableKey: string | undefined;
  try {
    supabasePublishableKey = publishableKeys
      ? (JSON.parse(publishableKeys) as Record<string, string>)["default"]
      : undefined;
  } catch {
    supabasePublishableKey = undefined;
  }
  supabasePublishableKey ??= Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ?? Deno.env.get("SUPABASE_ANON_KEY");
  const novuApiKey = Deno.env.get("NOVU_API_KEY");

  if (!supabaseUrl || !supabasePublishableKey || !novuApiKey) {
    console.error("[register-push-token] required server configuration is missing");
    return json(500, { error: "server_not_configured" });
  }

  const supabase = createClient(supabaseUrl, supabasePublishableKey, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
  });

  const { data: userData, error: userError } = await supabase.auth.getUser(accessToken);
  if (userError || !userData.user) {
    return json(401, { error: "invalid_session" });
  }

  let payload: unknown;
  try {
    payload = await req.json();
  } catch {
    return json(400, { error: "invalid_json" });
  }

  if (!payload || typeof payload !== "object") {
    return json(400, { error: "invalid_payload" });
  }

  const token = typeof (payload as { token?: unknown }).token === "string"
    ? (payload as { token: string }).token.trim()
    : "";
  const platform = typeof (payload as { platform?: unknown }).platform === "string"
    ? (payload as { platform: string }).platform.trim().toLowerCase()
    : "";
  const provider = typeof (payload as { provider?: unknown }).provider === "string"
    ? (payload as { provider: string }).provider.trim().toLowerCase()
    : "";

  if (!token || token.length > 4096) {
    return json(400, { error: "invalid_token" });
  }

  if (platform !== "android" || provider !== "fcm") {
    return json(400, { error: "unsupported_push_provider" });
  }

  const novuHeaders = {
    Authorization: `ApiKey ${novuApiKey}`,
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  // The app uses the Supabase auth user ID as the canonical Novu subscriber ID.
  // Creating the subscriber is idempotent, so token registration also works for
  // accounts that have never triggered a notification before.
  const subscriberResponse = await fetch("https://api.novu.co/v2/subscribers", {
    method: "POST",
    headers: novuHeaders,
    body: JSON.stringify({ subscriberId: userData.user.id }),
  });

  if (!subscriberResponse.ok) {
    const details = await subscriberResponse.text();
    console.error("[register-push-token] Novu subscriber upsert failed", subscriberResponse.status, details);
    return json(502, { error: "notification_provider_unavailable" });
  }

  // PATCH appends/deduplicates the device token instead of replacing another
  // device's token. Novu manages the provider credential set per subscriber.
  // Hash the token in the idempotency key so the raw device credential never
  // appears in a request header.
  const tokenDigest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  const tokenHash = Array.from(new Uint8Array(tokenDigest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  const credentialsResponse = await fetch(
    `https://api.novu.co/v1/subscribers/${encodeURIComponent(userData.user.id)}/credentials`,
    {
      method: "PATCH",
      headers: {
        ...novuHeaders,
        "idempotency-key": `fcm:${userData.user.id}:${tokenHash}`,
      },
      body: JSON.stringify({
        providerId: "fcm",
        credentials: { deviceTokens: [token] },
      }),
    },
  );

  if (!credentialsResponse.ok) {
    const details = await credentialsResponse.text();
    console.error("[register-push-token] Novu credential registration failed", credentialsResponse.status, details);
    return json(502, { error: "notification_provider_unavailable" });
  }

  return json(200, {
    ok: true,
    provider: "fcm",
    platform: "android",
  });
});
