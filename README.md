# 🔐 Digital Contract Manager

A secure web application for digitally signing and verifying contracts using cryptographic signatures. Built with FastAPI, Supabase, and modern cryptography standards.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)

## ✨ Features

- **🔐 End-to-End Encryption**: Private keys encrypted with AES-256-GCM
- **✍️ Digital Signatures**: RSA-PSS 2048-bit signatures with SHA-256
- **🔍 Instant Verification**: Verify contract authenticity in seconds
- **📊 Audit Trail**: Complete logging of all actions with timestamps and metadata
- **☁️ Cloud Storage**: Secure document storage with Supabase
- **🎨 Modern UI**: Clean, responsive interface built with vanilla JavaScript
- **🚀 Production Ready**: Docker support, comprehensive error handling, rate limiting

## 🏗️ Architecture

```
Frontend (HTML/CSS/JS) → FastAPI (Backend) → Supabase (PostgreSQL + Storage)
                              ↓
                     Cryptography Module
                     (RSA-PSS, AES-GCM)
```

## 📋 Prerequisites

- Python 3.11+
- Supabase account ([sign up free](https://supabase.com))
- Docker (optional, for containerized deployment)

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/contract-manager.git
cd contract-manager
```

### 2. Set Up Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure Supabase

1. Create a new project at [supabase.com](https://supabase.com)
2. Go to **Settings → API** and copy your:
   - Project URL
   - Anon/Public Key
3. Go to **SQL Editor** and run `supabase_schema.sql`
4. Go to **Storage** and verify `contracts` bucket was created

### 4. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your values:

```env
SECRET_KEY=your-secret-key-here  # Generate: openssl rand -hex 32
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key
```

### 5. Run Application

```bash
uvicorn app.main:app --reload
```

Visit: http://localhost:8000

## 🐳 Docker Deployment

### Build and Run

```bash
docker-compose up -d
```

### View Logs

```bash
docker-compose logs -f
```

### Stop

```bash
docker-compose down
```

## 📚 API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

#### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login and get tokens
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/auth/me` - Get current user info

#### Contracts
- `POST /api/contracts/upload` - Upload new contract
- `GET /api/contracts/` - List user contracts
- `GET /api/contracts/{id}` - Get contract details
- `POST /api/contracts/{id}/sign` - Sign contract
- `POST /api/contracts/verify` - Verify signature

#### Signing Keys
- `POST /api/keys/generate` - Generate key pair
- `GET /api/keys/` - List user keys
- `GET /api/keys/{id}` - Get key details
- `DELETE /api/keys/{id}` - Delete key

#### Audit
- `GET /api/audit/logs` - Get audit logs
- `GET /api/audit/dashboard` - Get dashboard stats

## 🔒 Security Features

### Cryptography

1. **Key Generation**: RSA 2048-bit keys using cryptography library
2. **Key Storage**: Private keys encrypted with AES-256-GCM
   - User password → PBKDF2 (100,000 iterations) → AES key
   - Unique salt and nonce per key
3. **Signing**: RSA-PSS with SHA-256 hashing
4. **Verification**: Public key verification without private key access

### Authentication

- JWT tokens with access (1 hour) and refresh (7 days) tokens
- Bcrypt password hashing with automatic salting
- Token refresh mechanism for seamless UX
- Secure session management

### API Security

- Rate limiting (100 requests/minute)
- CORS configuration
- Input validation with Pydantic
- SQL injection prevention (parameterized queries)
- XSS protection (Content Security Policy)

## 📁 Project Structure

```
contract-manager/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration settings
│   ├── api/                 # API endpoints
│   │   ├── auth.py          # Authentication
│   │   ├── contracts.py     # Contract management
│   │   ├── keys.py          # Key management
│   │   ├── users.py         # User management
│   │   └── audit.py         # Audit logs
│   ├── core/                # Core functionality
│   │   ├── crypto.py        # Cryptography module
│   │   ├── security.py      # Security utilities
│   │   └── supabase.py      # Supabase client
│   ├── models/              # Data models
│   │   └── schemas.py       # Pydantic schemas
│   └── services/            # Business logic
├── static/                  # Static files
│   ├── css/                 # Stylesheets
│   └── js/                  # JavaScript
├── templates/               # HTML templates
├── tests/                   # Test suite
├── requirements.txt         # Python dependencies
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose config
├── supabase_schema.sql     # Database schema
└── README.md              # This file
```

## 🧪 Testing

Run tests with pytest:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_crypto.py -v
```

## 🔧 Development

### Code Formatting

```bash
black app/
flake8 app/
mypy app/
```

### Database Migrations

If you modify the schema:

1. Update `supabase_schema.sql`
2. Run migrations in Supabase SQL Editor
3. Update models in `app/models/schemas.py`

## 📊 Monitoring & Logs

### Application Logs

```bash
# Docker
docker-compose logs -f app

# Local
tail -f app.log
```

### Audit Logs

View audit logs through:
- Dashboard → Recent Activity
- API: `GET /api/audit/logs`
- Supabase Dashboard → Table Editor → audit_logs

## 🚀 Deployment

### Environment Variables (Production)

```env
DEBUG=False
LOG_LEVEL=WARNING
CORS_ORIGINS=https://yourdomain.com
MAX_UPLOAD_SIZE=10485760
```

### Deployment Platforms

#### Render
1. Create new Web Service
2. Connect GitHub repository
3. Set environment variables
4. Deploy

#### Railway
```bash
railway init
railway add
railway up
```

#### Fly.io
```bash
fly launch
fly deploy
```

## 🛣️ Roadmap

- [ ] Multi-party signing (multiple signers per contract)
- [ ] Email notifications
- [ ] eKYC integration
- [ ] Blockchain timestamping
- [ ] Mobile app (React Native)
- [ ] PDF viewer with signature overlay
- [ ] Batch contract signing
- [ ] API webhooks
- [ ] Advanced analytics dashboard

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [Supabase](https://supabase.com/) - Backend as a Service
- [Cryptography](https://cryptography.io/) - Python cryptography library
- [Chart.js](https://www.chartjs.org/) - Data visualization

## 📧 Support

- 📫 Email: support@contractmanager.com
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/contract-manager/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/contract-manager/discussions)

## ⚠️ Security

Found a security vulnerability? Please email security@contractmanager.com instead of using the issue tracker.

---

Made with ❤️ by [Izu]