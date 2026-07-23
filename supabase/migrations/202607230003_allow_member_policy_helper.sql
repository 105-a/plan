-- The helper stays outside PostgREST's exposed schemas. Authenticated users need
-- only schema usage and function execution so RLS policies can evaluate it.
grant usage on schema private to authenticated;
grant execute on function private.is_active_member() to authenticated;
