# Authinticator Server

A secure TOTP (Time-based One-Time Password) authentication service built with Go, providing real-time 2FA code generation and management.

## Features

- **TOTP Code Generation**: Generate time-based one-time passwords for multiple services
- **Real-time Updates**: WebSocket support for live code updates
- **Secure Authentication**: Session-based authentication with HMAC-SHA256 signed tokens
- **Migration Support**: Import from Google Authenticator and other TOTP apps via QR codes
- **RESTful API**: Clean HTTP endpoints for service management
- **PostgreSQL Integration**: Persistent storage for user services and sessions

## Tech Stack

- **Backend**: Go 1.23+ with Gin web framework
- **Database**: PostgreSQL with pgx driver
- **WebSockets**: Gorilla WebSocket for real-time updates
- **TOTP**: pquerna/otp library for code generation
- **CORS**: Configurable cross-origin resource sharing
- **Deployment**: Docker and Vercel ready

## Quick Start

### Prerequisites

- Go 1.23 or higher
- PostgreSQL database
- Environment variables configured

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   go mod download
   ```

3. Set up environment variables (see Configuration section)

4. Run database migrations:
   ```bash
   pnpm run migrate
   ```

5. Start the server:
   ```bash
   pnpm start
   ```

### Development

```bash
# Start development server
pnpm start

# Build for production
pnpm run build:prod

# Run linting
pnpm run lint
```

## Configuration

Create a `.env` file with the following variables:

```env
DATABASE_URL=postgres://username:password@localhost:5432/dbname?sslmode=disable
SESSION_SECRET=your-secure-session-secret
LISTEN_ADDR=:8080
DEBUG=false
CORS_ORIGINS=*
CORS_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_HEADERS=Authorization,Content-Type,Origin,Accept
```

## API Endpoints

### Health Check
- `GET /health` - Server status check (no auth required)

### Authentication Services
- `GET /list` - List all user's authentication services
- `POST /add` - Add new authentication service
- `DELETE /delete?id=<service-id>` - Remove authentication service

### TOTP Codes
- `GET /code` - Get current TOTP codes (supports filtering by id/name)
- `GET /ws` - WebSocket endpoint for real-time code updates

### Authentication
All endpoints except `/health` require a valid session token cookie (`better-auth.session_token` or `session_token`).

## Docker Support

Use the included `docker-compose.yml` for local PostgreSQL:

```bash
docker-compose up -d
```

## Deployment

### Vercel
The project includes Vercel configuration for serverless deployment.

### Production Build
```bash
pnpm run build:prod
```

## Security Features

- HMAC-SHA256 signed session tokens
- Secure TOTP secret validation
- CORS protection
- SQL injection prevention with parameterized queries
- Environment-based configuration

## License

MIT License

