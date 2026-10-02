-- Native FCM device registration and durable push delivery.
create table if not exists public.app_push_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  token text not null,
  platform text not null check (platform in ('android','ios')),
  provider text not null check (provider in ('fcm','apns')),
  enabled boolean not null default true,
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(user_id, token)
);
create index if not exists app_push_tokens_user_idx on public.app_push_tokens(user_id) where enabled;
create index if not exists app_push_tokens_stale_idx on public.app_push_tokens(last_seen_at);
alter table public.app_push_tokens enable row level security;
revoke all on public.app_push_tokens from public, anon, authenticated;

create table if not exists public.notification_push_deliveries (
  id uuid primary key default gen_random_uuid(),
  notification_id uuid not null references public.notifications(id) on delete cascade,
  push_token_id uuid not null references public.app_push_tokens(id) on delete cascade,
  provider text not null,
  status text not null default 'pending' check(status in ('pending','processing','sent','failed')),
  attempts integer not null default 0,
  last_error text,
  next_attempt_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  sent_at timestamptz,
  unique(notification_id,push_token_id)
);
create index if not exists notification_push_deliveries_pending_idx on public.notification_push_deliveries(status,next_attempt_at,created_at);
alter table public.notification_push_deliveries enable row level security;
revoke all on public.notification_push_deliveries from public, anon, authenticated;

alter table public.notification_delivery_outbox add column if not exists updated_at timestamptz not null default now();

create or replace function public.claim_notification_delivery_batch(p_limit integer default 20)
returns table(id uuid,notification_id uuid,recipient_id uuid,event_name text,payload jsonb)
language plpgsql security definer set search_path=public,pg_temp as $$
begin
  return query
  with candidates as (
    select o.id from public.notification_delivery_outbox o
    where (o.status in ('pending','failed') and o.next_attempt_at <= now())
       or (o.status='processing' and o.updated_at < now()-interval '10 minutes')
    order by o.created_at for update skip locked
    limit greatest(1,least(coalesce(p_limit,20),50))
  )
  update public.notification_delivery_outbox o
  set status='processing',attempts=o.attempts+1,last_error=null,updated_at=now()
  from candidates c where o.id=c.id
  returning o.id,o.notification_id,o.recipient_id,o.event_name,o.payload;
end; $$;

create or replace function public.complete_notification_delivery(p_id uuid)
returns void language sql security definer set search_path=public,pg_temp as $$
 update public.notification_delivery_outbox set status='sent',sent_at=now(),next_attempt_at=now(),updated_at=now() where id=p_id;
$$;

create or replace function public.fail_notification_delivery(p_id uuid,p_error text)
returns void language sql security definer set search_path=public,pg_temp as $$
 update public.notification_delivery_outbox set status='failed',last_error=left(coalesce(p_error,'delivery failed'),500),
 next_attempt_at=now()+least(interval '1 hour',interval '5 seconds'*power(2,greatest(0,attempts-1))),updated_at=now() where id=p_id;
$$;

revoke all on function public.claim_notification_delivery_batch(integer) from public,anon,authenticated;
revoke all on function public.complete_notification_delivery(uuid) from public,anon,authenticated;
revoke all on function public.fail_notification_delivery(uuid,text) from public,anon,authenticated;
grant execute on function public.claim_notification_delivery_batch(integer) to service_role;
grant execute on function public.complete_notification_delivery(uuid) to service_role;
grant execute on function public.fail_notification_delivery(uuid,text) to service_role;

create or replace function public.prune_stale_app_push_tokens(p_days integer default 120)
returns integer language plpgsql security definer set search_path=public,pg_temp as $$
declare v_count integer;
begin
 delete from public.app_push_tokens where last_seen_at < now()-make_interval(days=>greatest(30,least(coalesce(p_days,120),365)));
 get diagnostics v_count=row_count; return v_count;
end; $$;
revoke all on function public.prune_stale_app_push_tokens(integer) from public,anon,authenticated;
grant execute on function public.prune_stale_app_push_tokens(integer) to service_role;

create or replace function public.get_notification_secret(p_name text)
returns text language plpgsql security definer set search_path=public,pg_temp as $$
declare v_secret text;
begin
 if current_user <> 'service_role' then raise exception using errcode='42501',message='service role required'; end if;
 select decrypted_secret into v_secret from vault.decrypted_secrets where name=trim(p_name) limit 1;
 return v_secret;
end; $$;
revoke all on function public.get_notification_secret(text) from public,anon,authenticated;
grant execute on function public.get_notification_secret(text) to service_role;
