# RNGdle Pocket

A private, phone-friendly remake of the RNGdle number game for a small group of friends.
Roll a number from 0 to 1,000,000; every property of the number earns a badge worth EP.

**Play:** https://whatmoehuh.github.io/rngdle/

- Only emails on the player list can sign in (the owner manages it under Stats → Player list).
- Each player's save is private; the leaderboard shows today, this month and all-time.
- Hosting: GitHub Pages. Sign-in and data: Supabase (free tier; pauses after a week without use).

`config.js` holds the Supabase project address and its public (anon/publishable) key.
Both are meant to be public: the database's row-level security rules decide who can read or write what.

Credits: badge rules modelled on rngdle.com. Bundled library: supabase-js 2.45.4 (MIT).
