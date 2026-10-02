-- Harden public SECURITY DEFINER execution boundaries and keep extensions out of the exposed public schema.
--
-- Trigger functions do not need API EXECUTE privileges.
revoke execute on function public.broadcast_stream_chat_message() from public, anon, authenticated;

-- These RPCs are intentionally callable by signed-in clients, but never anonymously.
revoke execute on function public.create_post_atomic_v3(jsonb) from public, anon;
grant execute on function public.create_post_atomic_v3(jsonb) to authenticated;

revoke execute on function public.testagram_create_local_reply(uuid, text) from public, anon;
grant execute on function public.testagram_create_local_reply(uuid, text) to authenticated;

revoke execute on function public.testagram_post_is_visible_to_viewer(uuid, uuid) from public, anon;
grant execute on function public.testagram_post_is_visible_to_viewer(uuid, uuid) to authenticated;

revoke execute on function public.testagram_toggle_local_like(uuid) from public, anon;
grant execute on function public.testagram_toggle_local_like(uuid) to authenticated;

revoke execute on function public.testagram_toggle_local_repost(uuid) from public, anon;
grant execute on function public.testagram_toggle_local_repost(uuid) to authenticated;

revoke execute on function public.tv_live_poll_results(uuid) from public, anon;
grant execute on function public.tv_live_poll_results(uuid) to authenticated;

alter extension pg_trgm set schema extensions;
