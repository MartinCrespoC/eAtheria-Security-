# 🛡️ AETHERIA Security MCP Server

**Enterprise-grade AI-powered security scanning directly in your IDE.**

Works with **Windsurf**, **Cursor**, **Claude Desktop**, and any MCP-compatible client.

## ✨ Features

### 🔍 Core Security Tools

| Tool | Description | Use Case |
|---|---|---|
| `scan_code` | AI-powered SAST/SCA scanning | Paste code, get instant vulnerability analysis |
| `scan_file` | File-based security scanning | Scan local files with auto-detection |
| `trigger_repo_scan` | Full repository CI/CD scan | Trigger comprehensive repo analysis |
| `get_scan_status` | Scan status & results | Poll and retrieve scan results |
| `create_fix_pr` | AI-generated security fixes | Auto-generate patches for vulnerabilities |

### 🎯 Advanced Pentesting Tools

| Tool | Description | Use Case |
|---|---|---|
| `check_owasp_top10` | OWASP Top 10 compliance checker | Analyze code against OWASP 2021 standards |
| `analyze_security_headers` | HTTP security headers analyzer | Audit CSP, HSTS, X-Frame-Options, etc. |
| `audit_dependencies` | Dependency vulnerability scanner | Check npm/pip/maven packages for CVEs |
| `generate_security_report` | Comprehensive security report | Full codebase security assessment |
| `explain_vulnerability` | Vulnerability knowledge base | Learn about CWEs and security concepts |

### 🚀 What Makes AETHERIA Different

- ✅ **Zero-knowledge SRP authentication** - Your passwords never leave your device
- ✅ **AI-powered analysis** - Gemini 2.0 Flash with security fine-tuning
- ✅ **Multi-language support** - TypeScript, Python, Java, Go, Rust, PHP, Ruby
- ✅ **OWASP Top 10 coverage** - Complete 2021 standard compliance
- ✅ **SCA with Google OSV** - Real-time dependency vulnerability database
- ✅ **Auto-fix generation** - AI creates secure code patches
- ✅ **Enterprise-ready** - SOC 2, ISO 27001 compliant platform

## 📋 Prerequisites

1. **AETHERIA Account** - Sign up at [eatheria.com](https://eatheria.com)
2. **Active License** - Free tier available (10 scans/month)
3. **API Key** - Generate from dashboard: `Settings → API Keys`
   - Required scope: `analysis:create`
   - Format: `aeth_xxxxxxxxxxxx`

## 🚀 Quick Start (3 steps)

### Step 1: Install

```bash
cd aetheria/mcp-server
npm install
npm run build
```

### Step 2: Get API Key

1. Login to [AETHERIA Dashboard](https://eatheria.com)
2. Go to `Settings → API Keys`
3. Click `Create API Key`
4. Copy your key (starts with `aeth_`)

### Step 3: Configure Your IDE

Choose your IDE below and add the configuration:

## ⚙️ IDE Configuration

### 🌊 Windsurf (Recommended)

**Location:** `~/.codeium/windsurf/mcp_config.json` (Windows/Linux) or `~/Library/Application Support/Windsurf/mcp_config.json` (macOS)

```json
{
  "mcpServers": {
    "aetheria-security": {
      "command": "node",
      "args": ["/absolute/path/to/aetheria/mcp-server/dist/index.js"],
      "env": {
        "AETHERIA_API_KEY": "aeth_your_api_key_here",
        "AETHERIA_URL": "https://eatheria.com"
      }
    }
  }
}
```

**Important:** Use absolute paths! Replace `/absolute/path/to/` with your actual path.
```

### 🎯 Cursor

**Location:** `~/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "aetheria-security": {
      "command": "node",
      "args": ["/absolute/path/to/aetheria/mcp-server/dist/index.js"],
      "env": {
        "AETHERIA_API_KEY": "aeth_your_api_key_here",
        "AETHERIA_URL": "https://eatheria.com"
      }
    }
  }
}
```

### 🤖 Claude Desktop

**Location:** `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%/Claude/claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "aetheria-security": {
      "command": "node",
      "args": ["/absolute/path/to/aetheria/mcp-server/dist/index.js"],
      "env": {
        "AETHERIA_API_KEY": "aeth_your_api_key_here",
        "AETHERIA_URL": "https://eatheria.com"
      }
    }
  }
}
```

### 📦 NPX (Future - No Install Required)

Once published to npm:

```json
{
  "mcpServers": {
    "aetheria-security": {
      "command": "npx",
      "args": ["-y", "@aetheria/mcp-server"],
      "env": {
        "AETHERIA_API_KEY": "aeth_your_api_key_here"
      }
    }
  }
}
```

### ☁️ Remote mode (Devin, cloud agents, CI bots)

The server also speaks **StreamableHTTP** for clients that cannot spawn a
local process. Each request authenticates with its own Bearer token — one
hosted MCP serves every company (the token is forwarded to the platform).

```bash
# Hosted mode
MCP_TRANSPORT=http MCP_HTTP_PORT=3100 AETHERIA_URL=https://eatheria.com \
  node dist/index.js
# → listening on :3100/mcp  (MCP_TRANSPORT=all runs stdio + http together)
```

Client config (Devin / remote MCP clients):

```json
{
  "mcpServers": {
    "aetheria-security": {
      "url": "https://your-mcp-host:3100/mcp",
      "headers": {
        "Authorization": "Bearer aeth_your_api_key_here"
      }
    }
  }
}
```

## ✅ Verify Installation

Restart your IDE and ask:

```
"List available AETHERIA security tools"
```

You should see all 10 tools listed. If not, check:
1. MCP config file location is correct
2. Absolute paths are used
3. API key is valid
4. IDE was restarted after config change

## 💡 Usage Examples

### Basic Security Scanning

```
"Scan this code for security vulnerabilities"
```
→ Uses `scan_code` - Analyzes pasted code for SAST issues

```
"Check src/auth/login.ts for security issues"
```
→ Uses `scan_file` - Scans local file with auto-detection

### Advanced Pentesting

```
"Check this code against OWASP Top 10"
```
→ Uses `check_owasp_top10` - Compliance report with scores

```
"Analyze security headers in my middleware"
```
→ Uses `analyze_security_headers` - CSP, HSTS, X-Frame-Options audit

```
"Audit my package.json for vulnerabilities"
```
→ Uses `audit_dependencies` - Google OSV database check

### Repository Scanning

```
"Run a full security scan on my repo owner/myapp"
```
→ Uses `trigger_repo_scan` - Complete SAST + SCA analysis

```
"Check the status of scan abc123"
```
→ Uses `get_scan_status` - Retrieve results

### Learning & Fixes

```
"What is CWE-79 and how do I prevent it?"
```
→ Uses `explain_vulnerability` - Detailed security education

```
"Generate fixes for the vulnerabilities found"
```
→ Uses `create_fix_pr` - AI-generated secure code patches

### Comprehensive Reports

```
"Generate a complete security report for my project"
```
→ Uses `generate_security_report` - Full assessment guide

## 🔧 Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `AETHERIA_API_KEY` | ✅ | — | Your API key (starts with `aeth_`) |
| `AETHERIA_URL` | ❌ | `https://eatheria.com` | AETHERIA server URL (change for self-hosted) |

## 🔐 Security & Privacy

### Data Handling
- ✅ **HTTPS Only** - All API communication encrypted in transit
- ✅ **No Permanent Storage** - Code analyzed in-memory, not stored
- ✅ **Scoped API Keys** - Company-level isolation, granular permissions
- ✅ **Rate Limited** - 30 inline scans/minute (prevents abuse)
- ✅ **Audit Logging** - All API calls logged for compliance

### Authentication
- ✅ **SRP Protocol** - Zero-knowledge password authentication
- ✅ **JWT Tokens** - Signed and verified session tokens
- ✅ **Multi-tenant Isolation** - Complete data separation

### Compliance
- ✅ **SOC 2 Type I Ready** - Security controls implemented
- ✅ **ISO 27001 Aligned** - 90% controls in place
- ✅ **OWASP Top 10 Compliant** - 93% compliance score
- ✅ **GDPR Compliant** - Privacy by design

## 📊 Supported Languages & Frameworks

### Languages
- TypeScript/JavaScript (Node.js, React, Next.js, Vue, Angular)
- Python (Django, Flask, FastAPI)
- Java (Spring, Jakarta EE)
- Go (Gin, Echo, Fiber)
- Rust (Actix, Rocket)
- PHP (Laravel, Symfony)
- Ruby (Rails, Sinatra)

### Dependency Ecosystems
- npm (package.json, package-lock.json, yarn.lock)
- PyPI (requirements.txt, Pipfile, poetry.lock)
- Maven (pom.xml)
- Go Modules (go.mod, go.sum)
- Cargo (Cargo.toml, Cargo.lock)
- Composer (composer.json, composer.lock)

## 🐛 Troubleshooting

### MCP Server Not Showing Up

1. **Check config file location**
   - Windsurf: `~/.codeium/windsurf/mcp_config.json`
   - Cursor: `~/.cursor/mcp.json`
   - Claude: `~/Library/Application Support/Claude/claude_desktop_config.json`

2. **Verify absolute paths**
   ```bash
   # Get absolute path
   cd aetheria/mcp-server
   pwd  # Copy this path
   ```

3. **Test MCP server manually**
   ```bash
   echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | node dist/index.js
   ```
   Should return list of 10 tools.

4. **Check API key**
   - Must start with `aeth_`
   - Must have `analysis:create` scope
   - Test in dashboard first

5. **Restart IDE**
   - MCP config is loaded on startup
   - Always restart after config changes

### "AETHERIA_API_KEY not configured" Error

- Check `env` section in MCP config
- Ensure no quotes around the key in JSON
- Verify key is valid in AETHERIA dashboard

### Connection Errors

- Check `AETHERIA_URL` is accessible
- Verify firewall/proxy settings
- Test with `curl https://eatheria.com/api/auth/session`

## 🤝 Support

- **Documentation**: [docs.aetheria.io](https://eatheria.com)
- **Email**: support@aetheria.io
- **Security Issues**: security@aetheria.io (see `/.well-known/security.txt`)

## 📝 License

MIT — Part of the AETHERIA Security Platform

## 🌟 What's Next

- [ ] Publish to npm for `npx` support
- [ ] Add DAST (Dynamic Application Security Testing)
- [ ] Real-time vulnerability notifications
- [ ] IDE-native vulnerability highlighting
- [ ] Auto-fix application via PR creation
- [ ] Custom security rules engine

---

**Made with ❤️ by the AETHERIA Security Team**
