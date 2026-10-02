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

-- Replace row-by-row auth.uid() evaluation with a statement-initplan form.
alter policy "tv_live_polls_host_delete" on public.tv_live_polls
  using (host_user_id = (select auth.uid()));

alter policy "tv_live_polls_host_insert" on public.tv_live_polls
  with check (
    host_user_id = (select auth.uid())
    and exists (
      select 1
      from public.live_streams s
      where s.id = tv_live_polls.stream_id
        and s.user_id = (select auth.uid())
        and s.is_live
    )
  );

alter policy "tv_live_polls_host_update" on public.tv_live_polls
  using (host_user_id = (select auth.uid()))
  with check (host_user_id = (select auth.uid()));

alter policy "tv_live_poll_votes_insert" on public.tv_live_poll_votes
  with check (
    voter_id = (select auth.uid())
    and exists (
      select 1
      from public.tv_live_polls p
      join public.live_streams s on s.id = p.stream_id
      where p.id = tv_live_poll_votes.poll_id
        and p.status = 'open'
        and s.is_live
        and (p.ends_at is null or now() < p.ends_at)
        and exists (
          select 1
          from jsonb_array_elements(p.options) o(value)
          where (o.value ->> 'id') = tv_live_poll_votes.option_id
        )
    )
  );

alter policy "tv_live_poll_votes_own_read" on public.tv_live_poll_votes
  using (voter_id = (select auth.uid()));

alter policy "tv_guest_invites_owner_insert" on public.tv_guest_invites
  with check (
    exists (
      select 1
      from public.live_streams s
      where s.id = tv_guest_invites.stream_id
        and s.user_id = (select auth.uid())
    )
  );

alter policy "tv_guest_invites_owner_read" on public.tv_guest_invites
  using (
    exists (
      select 1
      from public.live_streams s
      where s.id = tv_guest_invites.stream_id
        and s.user_id = (select auth.uid())
    )
  );

-- Cover every public-schema foreign key that does not already have a
-- left-prefix matching index. The generated names are deterministic.
do $$
declare
  r record;
begin
  for r in
    with fks as (
      select
        con.oid,
        n.nspname as schema_name,
        c.relname as table_name,
        array_agg(a.attname order by u.ord) as cols
      from pg_constraint con
      join pg_class c on c.oid = con.conrelid
      join pg_namespace n on n.oid = c.relnamespace
      join unnest(con.conkey) with ordinality u(attnum, ord) on true
      join pg_attribute a on a.attrelid = c.oid and a.attnum = u.attnum
      where con.contype = 'f'
        and n.nspname = 'public'
      group by con.oid, n.nspname, c.relname
    ),
    idx as (
      select
        i.indrelid,
        i.indexrelid,
        array_agg(a.attname order by x.ord) as cols
      from pg_index i
      join unnest(i.indkey) with ordinality x(attnum, ord) on true
      join pg_attribute a on a.attrelid = i.indrelid and a.attnum = x.attnum
      where i.indisvalid
      group by i.indrelid, i.indexrelid
    )
    select f.schema_name, f.table_name, f.cols
    from fks f
    where not exists (
      select 1
      from idx i
      where i.indrelid = (
        select c.oid
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = f.schema_name
          and c.relname = f.table_name
      )
      and i.cols[1:array_length(f.cols, 1)] = f.cols
    )
  loop
    execute format(
      'create index if not exists %I on %I.%I (%s)',
      'idx_fk_' || substr(md5(r.schema_name || '.' || r.table_name || ':' || array_to_string(r.cols, ',')), 1, 20),
      r.schema_name,
      r.table_name,
      (select string_agg(format('%I', x), ', ') from unnest(r.cols) as x)
    );
  end loop;
end $$;

-- Privileged governance mutations must require MFA.
create or replace function public.testagram_update_admin(p_user_id uuid, p_role_name text, p_status text default 'active', p_reason text default null)
returns jsonb
language plpgsql
security definer
set search_path=''
as $function$
declare v_role_id uuid;
begin
  if not public.testagram_is_owner() then raise exception 'Only the Testagram system owner can manage administrators'; end if;
  perform public.testagram_require_privileged_session();
  if p_user_id = (select auth.uid()) then raise exception 'The owner cannot be changed through administrator assignment'; end if;
  if p_status not in ('active','suspended','revoked') then raise exception 'Invalid administrator status'; end if;
  select id into v_role_id from public.testagram_governance_roles where name=p_role_name;
  if v_role_id is null then raise exception 'Unknown governance role'; end if;
  update public.testagram_governance_admin_assignments
  set role_id=v_role_id,status=p_status,
      employment_status=case when p_status='revoked' then 'terminated' when p_status='suspended' then 'suspended' else 'active' end,
      employment_ended_at=case when p_status='revoked' then now() else null end,
      updated_at=now(),revoked_at=case when p_status='revoked' then now() else null end
  where user_id=p_user_id;
  if not found then raise exception 'Administrator assignment not found'; end if;
  insert into public.testagram_governance_audit_log(actor_user_id,action,target_user_id,role_name,reason)
  values((select auth.uid()),case when p_status='revoked' then 'staff.terminated' when p_status='suspended' then 'staff.suspended' else 'staff.activated' end,p_user_id,p_role_name,coalesce(p_reason,'Owner governance change'));
  return public.testagram_get_governance_for_user(p_user_id);
end;
$function$;

create or replace function public.testagram_review_job_application(p_application_id uuid, p_status text, p_note text default null)
returns jsonb
language plpgsql
security definer
set search_path=''
as $function$
declare v_user uuid; v_role text;
begin
  if not public.testagram_is_owner() then raise exception 'Only the system owner can review job applications'; end if;
  perform public.testagram_require_privileged_session();
  if p_status not in ('reviewing','shortlisted','accepted','rejected','withdrawn') then raise exception 'Invalid application status'; end if;
  select user_id,role_name into v_user,v_role from public.testagram_job_applications where id=p_application_id for update;
  if v_user is null then raise exception 'Application not found'; end if;
  update public.testagram_job_applications
  set status=p_status,reviewed_by=(select auth.uid()),review_note=left(p_note,4000),updated_at=now()
  where id=p_application_id;
  insert into public.testagram_governance_audit_log(actor_user_id,action,target_user_id,role_name,reason,metadata)
  values((select auth.uid()),'job.application.reviewed',v_user,v_role,coalesce(p_note,'Owner reviewed application'),jsonb_build_object('application_id',p_application_id,'status',p_status));
  return jsonb_build_object('id',p_application_id,'status',p_status);
end;
$function$;
