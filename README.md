# Security Monitoring Dashboard

Security monitoring dashboard built with Laravel and Filament.

This repository contains the application inside the [`mcp-dashboard`](/Users/alifanurfika/Library/Mobile%20Documents/com~apple~CloudDocs/dashboard-project/mcp-dashboard) directory. The app reads scan output from JSON and presents:

- dashboard widgets for scan summary, severity, score, and findings
- cluster agent management
- security task creation and execution tracking
- task result table with task/time filtering

## Requirements

- PHP 8.3+
- Composer
- Node.js 20+ and npm
- SQLite

## Run The Project

1. Open the project and move into the Laravel app directory:

```bash
cd mcp-dashboard
```

2. Install PHP dependencies:

```bash
composer install
```

3. Install frontend dependencies:

```bash
npm install
```

4. Create the environment file:

```bash
cp .env.example .env
```

5. Create the SQLite database file if it does not exist yet:

```bash
touch database/database.sqlite
```

6. Generate the application key:

```bash
php artisan key:generate
```

7. Run database migrations and seed sample data:

```bash
php artisan migrate --seed
```

8. Start the Laravel server:

```bash
php artisan serve
```

9. In a separate terminal, start Vite for frontend assets:

```bash
npm run dev
```

10. Open the application:

- App: `http://127.0.0.1:8000`
- Admin panel: `http://127.0.0.1:8000/admin`

## Default Login

The seeder creates one default user:

- Email: `test@example.com`
- Password: `password`

## Optional One-Command Development Mode

You can also run the app with the built-in Composer script:

```bash
composer dev
```

This starts:

- Laravel development server
- queue listener
- log tailing
- Vite dev server

## Scan Data Source

The dashboard reads scan data from:

[`mcp-dashboard/storage/app/scan/results.json`](/Users/alifanurfika/Library/Mobile%20Documents/com~apple~CloudDocs/dashboard-project/mcp-dashboard/storage/app/scan/results.json)

If you want to test with different scan output, replace that file with a compatible JSON payload.

## Useful Pages

After logging in to Filament admin, you can access:

- Dashboard: `/admin`
- Cluster Agents: `/admin/cluster-agents`
- Security Tasks: `/admin/security-tasks`
- Task Results: `/admin/security-task-results`

## Build Assets For Production

```bash
npm run build
```

## Troubleshooting

If the app shows stale UI or config values, run:

```bash
php artisan optimize:clear
```
