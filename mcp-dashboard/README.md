# MCP Dashboard

This directory contains the Laravel + Filament application for the security monitoring dashboard.

For full setup and run instructions, see the repository README:

- [README.md](/Users/alifanurfika/Library/Mobile%20Documents/com~apple~CloudDocs/dashboard-project/README.md)

Quick start from this folder:

```bash
composer install
npm install
cp .env.example .env
touch database/database.sqlite
php artisan key:generate
php artisan migrate --seed
php artisan serve
```

Then in another terminal:

```bash
npm run dev
```

Admin URL:

- `http://127.0.0.1:8000/admin`
