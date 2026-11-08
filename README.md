# RNGdle Pocket

A private, phone-friendly remake of the RNGdle number game for a small group of friends.
Roll a number from 0 to 1,000,000; every property of the number earns a badge worth EP.

**Play:** https://whatmoehuh.github.io/rngdle/

- Anyone with the link can create an account with a username and password.
- Each player's save is private; the leaderboard shows today, this month and all-time.
- Hosting: GitHub Pages. Accounts and data: a Supabase database (free tier; pauses after a week without use).
- `supabase-setup.sql` creates the tables and the `rng_*` functions; the browser can only call those functions.

`config.js` holds the Supabase project address and its public (anon/publishable) key.
Both are meant to be public: the tables are locked, and the database functions check every request.

Credits: badge rules modelled on rngdle.com.
