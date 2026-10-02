create or replace function public.get_notification_secret(p_name text)
returns text
language plpgsql
security definer
set search_path=public,pg_temp
as $$
declare v_secret text;
begin
  select decrypted_secret into v_secret
  from vault.decrypted_secrets
  where name=trim(p_name)
  limit 1;
  return v_secret;
end;
$$;
revoke all on function public.get_notification_secret(text) from public,anon,authenticated;
grant execute on function public.get_notification_secret(text) to service_role;

select cron.unschedule('testagram-fcm-notification-worker');