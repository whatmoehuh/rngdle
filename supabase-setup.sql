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

-- 6. Seasons: lets the owner wipe all scores. Saves from an older season are refused, so phones can't upload old progress again.
create table if not exists public.rng_meta (
  id     boolean primary key default true check (id),
  season int not null default 1
);
insert into public.rng_meta (id) values (true) on conflict (id) do nothing;
alter table public.rng_meta enable row level security;
revoke all on public.rng_meta from anon, authenticated;

create or replace function public.rng_load(p_token text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := public.rng_session(p_token);
begin
  if a is null then raise exception 'signed_out'; end if;
  return json_build_object('id', a, 'username', (select display from public.rng_accounts where id = a),
                           'save', (select data from public.rng_saves where account_id = a),
                           'season', (select season from public.rng_meta),
                           'wait_ms', (select greatest(0, ceil(extract(epoch from next_roll_at - now()) * 1000)) from public.rng_accounts where id = a));
end $$;

drop function if exists public.rng_save(text, jsonb, jsonb);
create or replace function public.rng_save(p_token text, p_save jsonb, p_board jsonb, p_season int) returns void
  language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := public.rng_session(p_token);
begin
  if a is null then raise exception 'signed_out'; end if;
  if p_season is distinct from (select season from public.rng_meta) then raise exception 'new_season'; end if;
  if p_save is null or pg_column_size(p_save) > 300000 or pg_column_size(p_board) > 20000 then raise exception 'too_big'; end if;
  insert into public.rng_saves (account_id, data, updated_at) values (a, p_save, now())
    on conflict (account_id) do update set data = excluded.data, updated_at = now();
  if p_board is not null then
    insert into public.rng_board (account_id, data, updated_at) values (a, p_board, now())
      on conflict (account_id) do update set data = excluded.data, updated_at = now();
  end if;
end $$;
revoke all on function public.rng_save(text, jsonb, jsonb, int) from public;
grant execute on function public.rng_save(text, jsonb, jsonb, int) to anon, authenticated;

-- Owner only (run in the SQL Editor): wipes every save and the leaderboard, keeps all accounts.
create or replace function public.rng_reset_all() returns text
  language plpgsql security definer set search_path = public as $$
begin
  update public.rng_meta set season = season + 1;
  delete from public.rng_saves where true;
  delete from public.rng_board where true;
  return 'All scores deleted. New season: ' || (select season from public.rng_meta);
end $$;
revoke all on function public.rng_reset_all() from public, anon, authenticated;

-- 7. Rigged rolls (owner only): make a player's next rolls land on a chosen number. They don't count for anything.
create table if not exists public.rng_pranks (
  account_id uuid primary key references public.rng_accounts(id) on delete cascade,
  number     int not null check (number between 0 and 1000000),
  remaining  int not null check (remaining >= 0)
);
alter table public.rng_pranks enable row level security;
revoke all on public.rng_pranks from anon, authenticated;

create or replace function public.rng_roll(p_token text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := public.rng_session(p_token); nxt timestamptz; rigged int;
begin
  if a is null then raise exception 'signed_out'; end if;
  update public.rng_accounts set next_roll_at = now() + interval '10 seconds'
   where id = a and next_roll_at <= now()
  returning next_roll_at into nxt;
  if not found then
    select next_roll_at into nxt from public.rng_accounts where id = a;
    return json_build_object('ok', false, 'wait_ms', greatest(0, ceil(extract(epoch from nxt - now()) * 1000)));
  end if;
  update public.rng_pranks set remaining = remaining - 1
   where account_id = a and remaining > 0
  returning number into rigged;
  if rigged is not null then
    return json_build_object('ok', true, 'number', rigged, 'free', true,
                             'wait_ms', ceil(extract(epoch from nxt - now()) * 1000));
  end if;
  return json_build_object('ok', true, 'number', floor(random() * 1000001)::int,
                           'wait_ms', ceil(extract(epoch from nxt - now()) * 1000));
end $$;

-- select public.rng_prank('gurfild', 302539, 10);   -- next 10 rolls of gurfild are 302539
-- select public.rng_prank('gurfild', 0, 0);         -- stop it early
create or replace function public.rng_prank(p_username text, p_number int, p_times int) returns text
  language plpgsql security definer set search_path = public as $$
declare a uuid;
begin
  select id into a from public.rng_accounts where username = lower(trim(p_username));
  if a is null then return 'No player called ' || p_username; end if;
  insert into public.rng_pranks (account_id, number, remaining) values (a, p_number, greatest(p_times, 0))
    on conflict (account_id) do update set number = excluded.number, remaining = excluded.remaining;
  return case when p_times > 0 then 'Next ' || p_times || ' rolls of ' || p_username || ' will be ' || p_number || ' (not counted).'
              else 'Prank for ' || p_username || ' switched off.' end;
end $$;
revoke all on function public.rng_prank(text, int, int) from public, anon, authenticated;

-- 8. Daily crown: remembers everyone's best roll per day (German time); yesterday's best roller gets a crown on the leaderboard.
create table if not exists public.rng_daily (
  day        date not null,
  account_id uuid not null references public.rng_accounts(id) on delete cascade,
  best_ep    bigint not null,
  best_number int,
  reached_at timestamptz not null default now(),
  primary key (day, account_id)
);
alter table public.rng_daily enable row level security;
revoke all on public.rng_daily from anon, authenticated;

create or replace function public.rng_save(p_token text, p_save jsonb, p_board jsonb, p_season int) returns void
  language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := public.rng_session(p_token); d date; today date := (now() at time zone 'Europe/Berlin')::date; ep bigint;
begin
  if a is null then raise exception 'signed_out'; end if;
  if p_season is distinct from (select season from public.rng_meta) then raise exception 'new_season'; end if;
  if p_save is null or pg_column_size(p_save) > 300000 or pg_column_size(p_board) > 20000 then raise exception 'too_big'; end if;
  insert into public.rng_saves (account_id, data, updated_at) values (a, p_save, now())
    on conflict (account_id) do update set data = excluded.data, updated_at = now();
  if p_board is not null then
    insert into public.rng_board (account_id, data, updated_at) values (a, p_board, now())
      on conflict (account_id) do update set data = excluded.data, updated_at = now();
    -- remember the day's best (only for today, or yesterday for saves that arrive just after midnight)
    begin
      d := (p_board -> 'day' ->> 'key')::date;
      ep := (p_board -> 'day' ->> 'best_ep')::bigint;
    exception when others then d := null;
    end;
    if d in (today, today - 1) and ep > 0 then
      insert into public.rng_daily (day, account_id, best_ep, best_number) values (d, a, ep, (p_board -> 'day' ->> 'best_number')::int)
        on conflict (day, account_id) do update
          set best_number = case when excluded.best_ep > public.rng_daily.best_ep then excluded.best_number else public.rng_daily.best_number end,
              reached_at  = case when excluded.best_ep > public.rng_daily.best_ep then now() else public.rng_daily.reached_at end,
              best_ep     = greatest(public.rng_daily.best_ep, excluded.best_ep);
    end if;
  end if;
end $$;

create or replace function public.rng_board(p_token text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare champ uuid;
begin
  if public.rng_session(p_token) is null then raise exception 'signed_out'; end if;
  select account_id into champ from public.rng_daily
   where day = (now() at time zone 'Europe/Berlin')::date - 1
   order by best_ep desc, reached_at asc limit 1;                  -- a tie goes to whoever got there first
  return coalesce((select json_agg(json_build_object('id', b.account_id, 'username', a.display, 'data', b.data,
                                                     'crown', b.account_id = champ))
                     from public.rng_board b join public.rng_accounts a on a.id = b.account_id), '[]'::json);
end $$;

create or replace function public.rng_reset_all() returns text
  language plpgsql security definer set search_path = public as $$
begin
  update public.rng_meta set season = season + 1;
  delete from public.rng_saves where true;
  delete from public.rng_board where true;
  delete from public.rng_daily where true;
  return 'All scores deleted. New season: ' || (select season from public.rng_meta);
end $$;
revoke all on function public.rng_reset_all() from public, anon, authenticated;

-- 9. Leaderboard: also send each player's sum of daily bests for the current month (German time).
create or replace function public.rng_board(p_token text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare champ uuid; today date := (now() at time zone 'Europe/Berlin')::date;
begin
  if public.rng_session(p_token) is null then raise exception 'signed_out'; end if;
  select account_id into champ from public.rng_daily
   where day = today - 1
   order by best_ep desc, reached_at asc limit 1;                  -- a tie goes to whoever got there first
  return coalesce((
    select json_agg(json_build_object('id', b.account_id, 'username', a.display, 'data', b.data,
                                      'crown', b.account_id = champ,
                                      'month_daily', coalesce(m.total, 0), 'month_days', coalesce(m.days, 0)))
      from public.rng_board b
      join public.rng_accounts a on a.id = b.account_id
      left join (select account_id, sum(best_ep) as total, count(*) as days
                   from public.rng_daily
                  where day between date_trunc('month', today)::date and today
                  group by account_id) m on m.account_id = b.account_id), '[]'::json);
end $$;

-- Owner tools (run by hand in the SQL Editor when needed):
--   delete all scores (keeps accounts):  select public.rng_reset_all();
--   reset a password:  update public.rng_accounts set pw_hash = extensions.crypt('newpass123', extensions.gen_salt('bf', 10)) where username = 'name';
--   delete a player:   delete from public.rng_accounts where username = 'name';

-- ============================================================
-- RNGdle v1.0.2–v1.0.4 database changes in one go (safe to run more than once).
-- Written without "select … into" because the Supabase SQL editor mistakes that for creating a table.

-- v1.0.2: server-wide highscore places
create or replace function public.rng_rank(p_token text, p_ep bigint) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare
  dk text := to_char(now() at time zone 'Europe/Berlin', 'YYYY-MM-DD');
  mk text := to_char(now() at time zone 'Europe/Berlin', 'YYYY-MM');
  r_all int; r_month int; r_day int;
begin
  if public.rng_session(p_token) is null then raise exception 'signed_out'; end if;
  r_all := (select 1 + count(*)
    from public.rng_board b,
         jsonb_array_elements(case when jsonb_typeof(b.data -> 'top_all') = 'array' then b.data -> 'top_all'
                                   else jsonb_build_array(jsonb_build_object('ep', b.data -> 'best_ep')) end) e
   where (e ->> 'ep')::bigint >= p_ep);
  r_month := (select 1 + count(*)
    from public.rng_board b,
         jsonb_array_elements(case when jsonb_typeof(b.data -> 'month' -> 'top') = 'array' then b.data -> 'month' -> 'top'
                                   else jsonb_build_array(jsonb_build_object('ep', b.data -> 'month' -> 'best_ep')) end) e
   where b.data -> 'month' ->> 'key' = mk and (e ->> 'ep')::bigint >= p_ep);
  r_day := (select 1 + count(*)
    from public.rng_board b,
         jsonb_array_elements(case when jsonb_typeof(b.data -> 'day' -> 'top') = 'array' then b.data -> 'day' -> 'top'
                                   else jsonb_build_array(jsonb_build_object('ep', b.data -> 'day' -> 'best_ep')) end) e
   where b.data -> 'day' ->> 'key' = dk and (e ->> 'ep')::bigint >= p_ep);
  return json_build_object('all', r_all, 'month', r_month, 'day', r_day);
end $$;
revoke all on function public.rng_rank(text, bigint) from public;
grant execute on function public.rng_rank(text, bigint) to anon, authenticated;

-- v1.0.4: online dot
alter table public.rng_accounts add column if not exists last_seen timestamptz;

create or replace function public.rng_ping(p_token text, p_here boolean default true) returns void
  language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := public.rng_session(p_token);
begin
  if a is null then raise exception 'signed_out'; end if;
  update public.rng_accounts set last_seen = case when p_here then now() else null end where id = a;
end $$;
revoke all on function public.rng_ping(text, boolean) from public;
grant execute on function public.rng_ping(text, boolean) to anon, authenticated;

-- v1.0.3 + v1.0.4: leaderboard with streak crowns (0/1/2) and online flag
create or replace function public.rng_board(p_token text) returns json
  language plpgsql security definer set search_path = public, extensions as $$
declare
  today date := (now() at time zone 'Europe/Berlin')::date;
  champ uuid;
  champ2 uuid;
begin
  if public.rng_session(p_token) is null then raise exception 'signed_out'; end if;
  champ := (select account_id from public.rng_daily where day = today - 1
             order by best_ep desc, reached_at asc limit 1);          -- a tie goes to whoever got there first
  champ2 := (select account_id from public.rng_daily where day = today - 2
              order by best_ep desc, reached_at asc limit 1);
  return coalesce((
    select json_agg(json_build_object('id', b.account_id, 'username', a.display, 'data', b.data,
                                      'crown', b.account_id = champ,
                                      'crowns', case when b.account_id = champ and b.account_id = champ2 then 2
                                                     when b.account_id = champ then 1 else 0 end,
                                      'online', coalesce(a.last_seen > now() - interval '70 seconds', false),
                                      'month_daily', coalesce(m.total, 0), 'month_days', coalesce(m.days, 0)))
      from public.rng_board b
      join public.rng_accounts a on a.id = b.account_id
      left join (select account_id, sum(best_ep) as total, count(*) as days
                   from public.rng_daily
                  where day between date_trunc('month', today)::date and today
                  group by account_id) m on m.account_id = b.account_id), '[]'::json);
end $$;
