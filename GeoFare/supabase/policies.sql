
-- GeoFare Row Level Security policies
alter table public.profiles enable row level security;
alter table public.rider_profiles enable row level security;
alter table public.rider_verifications enable row level security;
alter table public.fare_matrix_versions enable row level security;
alter table public.fare_calculations enable row level security;
alter table public.ratings enable row level security;
alter table public.incidents enable row level security;
alter table public.audit_logs enable row level security;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists(select 1 from public.profiles p where p.id=auth.uid() and p.role='admin' and p.status='active');
$$;

-- Profiles
drop policy if exists profiles_select_own on public.profiles;
create policy profiles_select_own on public.profiles for select to authenticated
using (id=auth.uid() or public.is_admin());

drop policy if exists profiles_update_own on public.profiles;
create policy profiles_update_own on public.profiles for update to authenticated
using (id=auth.uid() or public.is_admin())
with check ((id=auth.uid() and role=(select role from public.profiles where id=auth.uid())) or public.is_admin());

drop policy if exists profiles_admin_all on public.profiles;
create policy profiles_admin_all on public.profiles for all to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Rider public information: only non-sensitive fields in rider_profiles are exposed.
drop policy if exists riders_select_verified on public.rider_profiles;
create policy riders_select_verified on public.rider_profiles for select to authenticated
using (verification_status='Verified' or profile_id=auth.uid() or public.is_admin());

drop policy if exists riders_insert_self on public.rider_profiles;
create policy riders_insert_self on public.rider_profiles for insert to authenticated
with check (profile_id=auth.uid() and exists(select 1 from public.profiles p where p.id=auth.uid() and p.role='rider'));

drop policy if exists riders_update_self_or_admin on public.rider_profiles;
create policy riders_update_self_or_admin on public.rider_profiles for update to authenticated
using (profile_id=auth.uid() or public.is_admin())
with check (profile_id=auth.uid() or public.is_admin());

-- Verification records
drop policy if exists verification_select on public.rider_verifications;
create policy verification_select on public.rider_verifications for select to authenticated
using (
  public.is_admin()
  or exists(select 1 from public.rider_profiles r where r.id=rider_id and r.profile_id=auth.uid())
);

drop policy if exists verification_admin_insert on public.rider_verifications;
create policy verification_admin_insert on public.rider_verifications for insert to authenticated
with check (public.is_admin() and reviewed_by=auth.uid());

-- Fare matrix: authenticated users can read active rows; only admin can manage.
drop policy if exists fare_select_active on public.fare_matrix_versions;
create policy fare_select_active on public.fare_matrix_versions for select to authenticated
using (status='active' or public.is_admin());

drop policy if exists fare_admin_manage on public.fare_matrix_versions;
create policy fare_admin_manage on public.fare_matrix_versions for all to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Fare calculations
drop policy if exists calculations_select_own on public.fare_calculations;
create policy calculations_select_own on public.fare_calculations for select to authenticated
using (user_id=auth.uid() or public.is_admin());

drop policy if exists calculations_insert_own on public.fare_calculations;
create policy calculations_insert_own on public.fare_calculations for insert to authenticated
with check (user_id=auth.uid());

-- Ratings: commuters create their own; rider sees their own ratings; admin monitors.
drop policy if exists ratings_select on public.ratings;
create policy ratings_select on public.ratings for select to authenticated
using (
  commuter_id=auth.uid()
  or public.is_admin()
  or exists(select 1 from public.rider_profiles r where r.id=rider_id and r.profile_id=auth.uid())
);

drop policy if exists ratings_insert_commuter on public.ratings;
create policy ratings_insert_commuter on public.ratings for insert to authenticated
with check (
  commuter_id=auth.uid()
  and exists(select 1 from public.profiles p where p.id=auth.uid() and p.role='commuter')
  and exists(select 1 from public.rider_profiles r where r.id=rider_id and r.verification_status='Verified')
);

-- Incident reports: owner can create/read; admin manages.
drop policy if exists incidents_select on public.incidents;
create policy incidents_select on public.incidents for select to authenticated
using (complainant_id=auth.uid() or public.is_admin());

drop policy if exists incidents_insert on public.incidents;
create policy incidents_insert on public.incidents for insert to authenticated
with check (complainant_id=auth.uid());

drop policy if exists incidents_admin_update on public.incidents;
create policy incidents_admin_update on public.incidents for update to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Audit logs are administrative only.
drop policy if exists audit_admin_select on public.audit_logs;
create policy audit_admin_select on public.audit_logs for select to authenticated
using (public.is_admin());

drop policy if exists audit_admin_insert on public.audit_logs;
create policy audit_admin_insert on public.audit_logs for insert to authenticated
with check (public.is_admin() and user_id=auth.uid());

-- Revoke broad anonymous access to application tables.
revoke all on public.profiles,public.rider_profiles,public.rider_verifications,
  public.fare_matrix_versions,public.fare_calculations,public.ratings,
  public.incidents,public.audit_logs from anon;
