GEOFARE READY-TO-CONNECT PACKAGE

Files:
- index.html
- config.js
- supabase/schema.sql
- supabase/policies.sql

Setup:
1. Open Supabase -> SQL Editor and run supabase/schema.sql.
2. Run supabase/policies.sql.
3. Put this entire folder in C:\xampp\htdocs\GeoFare.
4. Start Apache in XAMPP.
5. Open http://localhost/GeoFare/

Supabase credentials are already placed in config.js using the public/anon browser key.
Never replace it with a service-role or secret key.

External browser libraries are loaded by index.html from their CDN URLs. No duplicate local library copies are included.
