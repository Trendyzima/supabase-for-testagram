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
