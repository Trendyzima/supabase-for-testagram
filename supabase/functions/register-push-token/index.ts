import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.51.0";
const corsHeaders={"Access-Control-Allow-Origin":"https://testagram.site","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Content-Type":"application/json"};
const json=(status:number,body:Record<string,unknown>)=>new Response(JSON.stringify(body),{status,headers:corsHeaders});
Deno.serve(async(req)=>{
 if(req.method==="OPTIONS") return new Response("ok",{headers:corsHeaders});
 if(req.method!=="POST") return json(405,{error:"method_not_allowed"});
 const accessToken=req.headers.get("Authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
 if(!accessToken) return json(401,{error:"missing_authorization"});
 let body:unknown; try{body=await req.json();}catch{return json(400,{error:"invalid_json"});}
 if(!body||typeof body!=="object") return json(400,{error:"invalid_payload"});
 const input=body as Record<string,unknown>;
 const token=typeof input.token==="string"?input.token.trim():"";
 const platform=typeof input.platform==="string"?input.platform.trim().toLowerCase():"";
 const provider=typeof input.provider==="string"?input.provider.trim().toLowerCase():"";
 if(!token||token.length>4096) return json(400,{error:"invalid_token"});
 if(platform!=="android"||provider!=="fcm") return json(400,{error:"unsupported_push_provider"});
 const url=Deno.env.get("SUPABASE_URL");
 const publishableKey=Deno.env.get("SUPABASE_PUBLISHABLE_KEY")??Deno.env.get("SUPABASE_ANON_KEY");
 const serviceRoleKey=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
 if(!url||!publishableKey||!serviceRoleKey) return json(500,{error:"server_not_configured"});
 const authClient=createClient(url,publishableKey,{auth:{persistSession:false,autoRefreshToken:false},global:{headers:{Authorization:"Bearer "+accessToken}}});
 const {data:userData,error:userError}=await authClient.auth.getUser(accessToken);
 if(userError||!userData.user) return json(401,{error:"invalid_session"});
 const admin=createClient(url,serviceRoleKey,{auth:{persistSession:false,autoRefreshToken:false}});
 const now=new Date().toISOString();
 const {error}=await admin.from("app_push_tokens").upsert({user_id:userData.user.id,token,platform:"android",provider:"fcm",enabled:true,last_seen_at:now,updated_at:now},{onConflict:"user_id,token"});
 if(error){console.error("[register-push-token] token persistence failed:",error.message);return json(500,{error:"token_registration_failed"});}
 return json(200,{ok:true,provider:"fcm",platform:"android"});
});
