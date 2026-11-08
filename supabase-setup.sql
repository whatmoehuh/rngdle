-- RNGdle: username + password accounts, private saves and a shared leaderboard.
-- Paste all of this into Supabase → SQL Editor → New query, then tap "Run". Running it twice is harmless.
-- The browser never touches the tables directly: it can only call the rng_* functions at the bottom.

-- 1. Remove the earlier email-based setup (it held no game data yet)
drop trigger  if exists on_player_removed on public.players_allowed;
drop table    if exists public.board, public.saves, public.players_allowed cascade;
drop function if exists public.drop_removed_player(), public.is_player(), public.is_admin(), public.my_email();

-- 2. Tables
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.rng_accounts (
  id         uuid primary key default gen_random_uuid(),
  username   text not null unique check (username ~ '^[a-z0-9_]{3,20}$'),   -- lowercase, for logging in
  display    text not null,                                                   -- as typed, for showing
  pw_hash    text not null,                                                   -- bcrypt, never the password
  created_at timestamptz not null default now()
);
create table if not exists public.rng_sessions (
  token_hash text primary key,                                                -- sha256 of the sign-in token
  account_id uuid not null references public.rng_accounts(id) on delete cascade,
  created_at timestamptz not null default now(),
  last_used  timestamptz not null default now()
);
create table if not exists public.rng_saves (
  account_id uuid primary key references public.rng_accounts(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
create table if not exists public.rng_board (
  account_id uuid primary key references public.rng_accounts(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);

-- Row-level security on, and no policies: nobody can read or write these tables directly.
alter table public.rng_accounts enable row level security;
alter table public.rng_sessions enable row level security;
alter table public.rng_saves    enable row level security;
alter table public.rng_board    enable row level security;
revoke all on public.rng_accounts, public.rng_sessions, public.rng_saves, public.rng_board from anon, authenticated;

-- 3. Internal helpers (not callable from the website)
create or replace function public.rng_session(p_token text) returns uuid
  language sql security definer set search_path = public, extensions as $$
  update public.rng_sessions set last_used = now()
   where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
  returning account_id $$;

create or replace function public.rng_new_session(p_account uuid) returns text
  language plpgsql security definer set search_path = public, extensions as $$
declare t text := encode(extensions.gen_random_bytes(32), 'hex');
begin
  insert into public.rng_sessions (token_hash, account_id) values (encode(extensions.digest(t, 'sha256'), 'hex'), p_account);
  return t;
end $$;

revoke all on function public.rng_session(text), public.rng_new_session(uuid) from public, anon, authenticated;

-- 4. What the website may call
create or replace function public.rng_register(p_username text, p_password text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare u text := lower(trim(coalesce(p_username, ''))); a uuid;
begin
  if u !~ '^[a-z0-9_]{3,20}$' then raise exception 'bad_username'; end if;
  if length(coalesce(p_password, '')) < 6 or length(p_password) > 72 then raise exception 'bad_password'; end if;
  begin
    insert into public.rng_accounts (username, display, pw_hash)
    values (u, trim(p_username), extensions.crypt(p_password, extensions.gen_salt('bf', 10)))
    returning id into a;
  exception when unique_violation then raise exception 'username_taken';
  end;
  return json_build_object('token', public.rng_new_session(a), 'id', a, 'username', trim(p_username), 'save', null);
end $$;

create or replace function public.rng_login(p_username text, p_password text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare acc public.rng_accounts;
begin
  select * into acc from public.rng_accounts where username = lower(trim(coalesce(p_username, '')));
  if not found or acc.pw_hash <> extensions.crypt(coalesce(p_password, ''), acc.pw_hash) then raise exception 'wrong_login'; end if;
  return json_build_object('token', public.rng_new_session(acc.id), 'id', acc.id, 'username', acc.display,
                           'save', (select data from public.rng_saves where account_id = acc.id));
end $$;

create or replace function public.rng_load(p_token text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := public.rng_session(p_token);
begin
  if a is null then raise exception 'signed_out'; end if;
  return json_build_object('id', a, 'username', (select display from public.rng_accounts where id = a),
                           'save', (select data from public.rng_saves where account_id = a));
end $$;

create or replace function public.rng_save(p_token text, p_save jsonb, p_board jsonb) returns void
  language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := public.rng_session(p_token);
begin
  if a is null then raise exception 'signed_out'; end if;
  if p_save is null or pg_column_size(p_save) > 300000 or pg_column_size(p_board) > 20000 then raise exception 'too_big'; end if;
  insert into public.rng_saves (account_id, data, updated_at) values (a, p_save, now())
    on conflict (account_id) do update set data = excluded.data, updated_at = now();
  if p_board is not null then
    insert into public.rng_board (account_id, data, updated_at) values (a, p_board, now())
      on conflict (account_id) do update set data = excluded.data, updated_at = now();
  end if;
end $$;

create or replace function public.rng_board(p_token text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
begin
  if public.rng_session(p_token) is null then raise exception 'signed_out'; end if;
  return coalesce((select json_agg(json_build_object('id', b.account_id, 'username', a.display, 'data', b.data))
                     from public.rng_board b join public.rng_accounts a on a.id = b.account_id), '[]'::json);
end $$;

create or replace function public.rng_logout(p_token text) returns void
  language sql security definer set search_path = public, extensions as $$
  delete from public.rng_sessions where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') $$;

revoke all on function public.rng_register(text, text), public.rng_login(text, text), public.rng_load(text),
  public.rng_save(text, jsonb, jsonb), public.rng_board(text), public.rng_logout(text) from public;
grant execute on function public.rng_register(text, text), public.rng_login(text, text), public.rng_load(text),
  public.rng_save(text, jsonb, jsonb), public.rng_board(text), public.rng_logout(text) to anon, authenticated;

-- 5. Server-side rolls with a cooldown: numbers come from the database, at most one roll per 10 seconds per account.
alter table public.rng_accounts add column if not exists next_roll_at timestamptz not null default now();

create or replace function public.rng_roll(p_token text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := public.rng_session(p_token); nxt timestamptz;
begin
  if a is null then raise exception 'signed_out'; end if;
  update public.rng_accounts set next_roll_at = now() + interval '10 seconds'     -- ← the cooldown
   where id = a and next_roll_at <= now()
  returning next_roll_at into nxt;
  if not found then
    select next_roll_at into nxt from public.rng_accounts where id = a;
    return json_build_object('ok', false, 'wait_ms', greatest(0, ceil(extract(epoch from nxt - now()) * 1000)));
  end if;
  return json_build_object('ok', true, 'number', floor(random() * 1000001)::int,
                           'wait_ms', ceil(extract(epoch from nxt - now()) * 1000));
end $$;

create or replace function public.rng_load(p_token text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := public.rng_session(p_token);
begin
  if a is null then raise exception 'signed_out'; end if;
  return json_build_object('id', a, 'username', (select display from public.rng_accounts where id = a),
                           'save', (select data from public.rng_saves where account_id = a),
                           'wait_ms', (select greatest(0, ceil(extract(epoch from next_roll_at - now()) * 1000)) from public.rng_accounts where id = a));
end $$;

revoke all on function public.rng_roll(text) from public;
grant execute on function public.rng_roll(text) to anon, authenticated;

-- Owner tools (run by hand in the SQL Editor when needed):
--   reset a password:  update public.rng_accounts set pw_hash = extensions.crypt('newpass123', extensions.gen_salt('bf', 10)) where username = 'name';
--   delete a player:   delete from public.rng_accounts where username = 'name';
