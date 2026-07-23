create schema if not exists private;

revoke all on schema private from public, anon, authenticated;

create or replace function private.is_active_member()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.team_members
    where id = (select auth.uid())
  );
$$;

revoke all on function private.is_active_member() from public, anon, authenticated, service_role;

drop policy if exists active_members_can_read_team_members on public.team_members;
drop policy if exists active_members_can_read_calendar_events on public.calendar_events;
drop policy if exists active_members_can_create_calendar_events on public.calendar_events;
drop policy if exists active_members_can_update_calendar_events on public.calendar_events;
drop policy if exists active_members_can_delete_calendar_events on public.calendar_events;

create policy active_members_can_read_team_members
on public.team_members
for select
to authenticated
using ((select private.is_active_member()));

create policy active_members_can_read_calendar_events
on public.calendar_events
for select
to authenticated
using ((select private.is_active_member()));

create policy active_members_can_create_calendar_events
on public.calendar_events
for insert
to authenticated
with check (
  (select private.is_active_member())
  and created_by = (select auth.uid())
);

create policy active_members_can_update_calendar_events
on public.calendar_events
for update
to authenticated
using ((select private.is_active_member()))
with check ((select private.is_active_member()));

create policy active_members_can_delete_calendar_events
on public.calendar_events
for delete
to authenticated
using ((select private.is_active_member()));

drop function if exists public.is_active_member();
