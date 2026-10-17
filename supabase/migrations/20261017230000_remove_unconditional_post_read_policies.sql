-- Remove unconditional SELECT policies that bypass post visibility rules.
-- Keep posts_public_read and post_media_public_read, which delegate to
-- testagram_post_is_visible_to_viewer and preserve legitimate public visibility.
begin;

drop policy if exists secondary_posts_public_read on public.posts;
drop policy if exists secondary_post_media_public_read on public.post_media;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'posts'
      and policyname = 'posts_public_read'
      and cmd = 'SELECT'
      and qual like '%testagram_post_is_visible_to_viewer%'
  ) then
    raise exception 'Expected visibility-aware posts_public_read policy is missing';
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'post_media'
      and policyname = 'post_media_public_read'
      and cmd = 'SELECT'
      and qual like '%testagram_post_is_visible_to_viewer%'
  ) then
    raise exception 'Expected visibility-aware post_media_public_read policy is missing';
  end if;
end
$$;

commit;
