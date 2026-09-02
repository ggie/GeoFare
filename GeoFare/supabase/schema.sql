
-- GeoFare PostgreSQL schema for Supabase
-- Research scope: fare computation + fare management + public safety/accountability.
create extension if not exists pgcrypto;

create type public.app_role as enum ('commuter','rider','admin');
create type public.verification_status as enum ('Pending','Verified','Rejected','Suspended');
create type public.report_status as enum ('New','Under Review','Resolved','Dismissed');

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  email text,
  role public.app_role not null default 'commuter',
  contact_number text,
  address text,
  status text not null default 'active' check (status in ('active','inactive','suspended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.rider_profiles (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null unique references public.profiles(id) on delete cascade,
  public_id text not null unique,
  public_name text not null,
  business_permit_reference text,
  service_area text,
  verification_status public.verification_status not null default 'Pending',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.rider_verifications (
  id uuid primary key default gen_random_uuid(),
  rider_id uuid not null references public.rider_profiles(id) on delete cascade,
  reviewed_by uuid references public.profiles(id),
  status public.verification_status not null,
  review_note text,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.fare_matrix_versions (
  id uuid primary key default gen_random_uuid(),
  version_code text not null,
  minimum_distance numeric(8,3) not null check (minimum_distance > 0),
  maximum_distance numeric(8,3) not null check (maximum_distance >= minimum_distance),
  regular_fare numeric(10,2) not null check (regular_fare >= 0),
  discounted_fare numeric(10,2) not null check (discounted_fare >= 0),
  effective_from timestamptz,
  effective_until timestamptz,
  status text not null default 'draft' check (status in ('draft','active','archived')),
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.fare_calculations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  pickup text not null,
  dropoff text not null,
  pickup_lat numeric(10,7) not null,
  pickup_lng numeric(10,7) not null,
  dropoff_lat numeric(10,7) not null,
  dropoff_lng numeric(10,7) not null,
  distance_km numeric(10,3) not null check (distance_km > 0),
  regular_fare numeric(10,2) not null check (regular_fare >= 0),
  discounted_fare numeric(10,2) not null check (discounted_fare >= 0),
  fare_matrix_version uuid references public.fare_matrix_versions(id),
  routing_provider text not null default 'OSRM',
  calculated_at timestamptz not null default now()
);

create table if not exists public.ratings (
  id uuid primary key default gen_random_uuid(),
  commuter_id uuid not null references public.profiles(id) on delete cascade,
  rider_id uuid not null references public.rider_profiles(id) on delete cascade,
  professionalism smallint not null check (professionalism between 1 and 5),
  safety smallint not null check (safety between 1 and 5),
  punctuality smallint not null check (punctuality between 1 and 5),
  service_quality smallint not null check (service_quality between 1 and 5),
  comment text check (char_length(comment) <= 500),
  trip_reference text,
  created_at timestamptz not null default now()
);

create table if not exists public.incidents (
  id uuid primary key default gen_random_uuid(),
  reference_no text not null unique,
  complainant_id uuid not null references public.profiles(id) on delete cascade,
  rider_reference text,
  category text not null check (category in ('overcharging','refuse-discount','rude-conduct','unsafe-driving','other')),
  incident_datetime timestamptz not null,
  location_text text,
  description text not null check (char_length(description) between 5 and 5000),
  status public.report_status not null default 'New',
  administrative_note text,
  resolved_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  action text not null,
  target_type text,
  target_id text,
  previous_value jsonb,
  new_value jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_fare_active on public.fare_matrix_versions(status,effective_from);
create index if not exists idx_calcs_user on public.fare_calculations(user_id,calculated_at desc);
create index if not exists idx_rider_verification on public.rider_profiles(verification_status);
create index if not exists idx_incidents_status on public.incidents(status,created_at desc);
create index if not exists idx_ratings_rider on public.ratings(rider_id,created_at desc);

-- New-account trigger. Public sign-up may create only commuter or rider accounts.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare requested_role text := coalesce(new.raw_user_meta_data->>'role','commuter');
declare final_role public.app_role;
begin
  if requested_role = 'rider' then final_role := 'rider';
  else final_role := 'commuter'; -- admin can only be assigned separately by an authorized administrator.
  end if;

  insert into public.profiles(id,full_name,email,role,contact_number,address)
  values(
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name','User'),
    new.email,
    final_role,
    new.raw_user_meta_data->>'contact_number',
    new.raw_user_meta_data->>'address'
  );

  if final_role='rider' then
    insert into public.rider_profiles(profile_id,public_id,public_name,business_permit_reference,service_area)
    values(
      new.id,
      'RDR-' || upper(substr(replace(new.id::text,'-',''),1,8)),
      coalesce(new.raw_user_meta_data->>'full_name','Rider'),
      new.raw_user_meta_data->>'business_permit_reference',
      new.raw_user_meta_data->>'service_area'
    );
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Keep updated_at current.
create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end; $$;

drop trigger if exists profiles_touch on public.profiles;
create trigger profiles_touch before update on public.profiles for each row execute procedure public.touch_updated_at();
drop trigger if exists riders_touch on public.rider_profiles;
create trigger riders_touch before update on public.rider_profiles for each row execute procedure public.touch_updated_at();
drop trigger if exists fare_touch on public.fare_matrix_versions;
create trigger fare_touch before update on public.fare_matrix_versions for each row execute procedure public.touch_updated_at();
drop trigger if exists incident_touch on public.incidents;
create trigger incident_touch before update on public.incidents for each row execute procedure public.touch_updated_at();
