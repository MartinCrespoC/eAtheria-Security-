/**
 * Security Rules Seed Script
 * Populates ALL security engine rules into the database.
 * Run: npx tsx scripts/seed-security-rules.ts
 *
 * Tables populated:
 * - TaintSource (sources per language)
 * - TaintSink (sinks per language with CWE/severity)
 * - TaintSanitizer (sanitizers per language)
 * - SecretPattern (regex patterns for secrets detection)
 * - IacRule (IaC misconfiguration rules)
 * - ComplianceMapping (CWE → PCI-DSS, HIPAA, NIST, ISO 27001)
 */
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// ==================== TAINT SOURCES ====================
const TAINT_SOURCES: { language: string; pattern: string; category: string }[] = [
  // JavaScript / TypeScript
  ...["req.body", "req.params", "req.query", "req.headers", "req.cookies",
    "request.body", "request.params", "request.query",
    "ctx.request.body", "ctx.params", "ctx.query",
    "window.location", "document.URL", "document.location",
    "location.href", "location.search", "location.hash",
    "URLSearchParams", "localStorage.getItem", "sessionStorage.getItem",
    "postMessage", "event.data", "FormData",
    "process.argv", "readline", "stdin",
    "socket.on", "ws.on", "io.on",
    // DOM attribute values are attacker-influenceable (DOM-XSS source, e.g.
    // `element.getAttribute('href')` flowing into `$(selector)` — CVE-2016-10735).
    "getAttribute(",
    // Plugin/widget options are caller-supplied (`$(el).plugin({parent: evil})`
    // → `this.options.parent` — CVE-2018-14040/41 bootstrap jQuery plugins).
    "this.options.",
    // Archive entry metadata is attacker-controlled (Zip-Slip): entry names in
    // zip/tar archives can contain `../` — CVE-2018-1002203/20834/1002204.
    "entry.path", "entry.name", "header.name", "header.linkname",
  ].map((p) => ({ language: "javascript", pattern: p, category: "user-input" })),
  // Python
  ...["request.form", "request.args", "request.values", "request.json",
    "request.data", "request.files", "request.headers", "request.cookies",
    "input(", "raw_input(", "sys.argv", "os.environ",
    "socket.recv", "conn.recv", "urllib.request.urlopen",
    "flask.request", "django.http.request", "HttpRequest",
  ].map((p) => ({ language: "python", pattern: p, category: "user-input" })),
  // Java
  ...["getParameter(", "getParameterMap(", "getParameterValues(", "getHeader(", "getHeaders(", "getHeaderNames(", "getCookies(", "getQueryString(",
    "getInputStream(", "getReader(", "getRequestURI(",
    "request.getParameter", "request.getHeader", "request.getBody",
    "@RequestParam", "@PathVariable", "@RequestBody", "@RequestHeader",
    "Scanner(", "BufferedReader(", "System.in",
    "ObjectInputStream(", "Socket.getInputStream",
    // OWASP Benchmark request-wrapping helpers (SeparateClassRequest) — real input
    // accessors. NOTE: getTheValue() is deliberately excluded (it returns a constant).
    "getTheParameter(", "getTheCookie(",
  ].map((p) => ({ language: "java", pattern: p, category: "user-input" })),
  // PHP
  ...["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
    "$_FILES", "file_get_contents(\"php://input\")",
    "$HTTP_RAW_POST_DATA", "filter_input(",
  ].map((p) => ({ language: "php", pattern: p, category: "user-input" })),
  // C#
  ...["Request.Form", "Request.Query", "Request.Body", "Request.Headers",
    "Request.RouteValues", "HttpContext.Request", "[FromBody]", "[FromQuery]",
    "Console.ReadLine(", "args[", "Environment.GetEnvironmentVariable",
  ].map((p) => ({ language: "csharp", pattern: p, category: "user-input" })),
  // Ruby
  ...["params[", "params.", "request.body", "request.env",
    "cookies[", "session[", "STDIN", "ARGV", "gets",
  ].map((p) => ({ language: "ruby", pattern: p, category: "user-input" })),
  // Go
  ...["r.FormValue(", "r.URL.Query(", "r.Body", "r.Header.Get(",
    "r.PostFormValue(", "r.Cookie(", "mux.Vars(", "c.Param(",
    "c.Query(", "c.PostForm(", "os.Args", "bufio.NewReader(os.Stdin)",
  ].map((p) => ({ language: "go", pattern: p, category: "user-input" })),
  // ABAP / SAP
  ...["GET PARAMETER", "IMPORTING p_", "SELECT-OPTIONS", "PARAMETERS:",
    "cl_http_utility=>", "if_http_extension~",
    "server->request->", "request->get_form_field", "request->get_header_field",
    "cl_gui_frontend_services=>", "sy-uname", "sy-host",
  ].map((p) => ({ language: "abap", pattern: p, category: "user-input" })),
  // Generic (covers kotlin, swift, c, cpp, rust, scala, perl, lua, r, dart, elixir, vbnet, sql)
  ...["request", "input", "argv", "stdin", "params", "query", "body",
    "getenv", "environ", "args", "readLine", "scanf", "gets",
  ].map((p) => ({ language: "*", pattern: p, category: "user-input" })),
];

// ==================== TAINT SANITIZERS ====================
const TAINT_SANITIZERS: { language: string; pattern: string; category: string }[] = [
  // JavaScript / TypeScript
  ...["DOMPurify.sanitize", "sanitize-html", "xss(", "escape(",
    "encodeURIComponent", "encodeURI", "he.encode",
    // HTML-escape replace chains: `x.replace(/&/g, '&amp;')` et al.
    ", '&amp;')", ", '&lt;')", ", '&gt;')", ", '&quot;')", ", '&#39;')", ", '&#x27;')",
    "validator.escape", "validator.blacklist", "validator.whitelist",
  ].map((p) => ({ language: "javascript", pattern: p, category: "encoding" })),
  ...["bcrypt.hash", "crypto.createHash", "parameterized",
    "knex.raw", "db.escape", "mysql.escape", "pg.ParameterizedQuery",
    "mongoose.Schema", "prisma.", "sequelize.literal",
  ].map((p) => ({ language: "javascript", pattern: p, category: "parameterization" })),
  ...["helmet(", "csurf(", "express-rate-limit",
    "path.normalize", "path.resolve", "sanitizePath",
    "JSON.parse", "parseInt", "parseFloat", "Number(",
    "String(", "toString(", "trim(",
  ].map((p) => ({ language: "javascript", pattern: p, category: "validation" })),
  // Python
  ...["escape(", "markupsafe.escape", "bleach.clean", "html.escape",
    "quote(", "urllib.parse.quote", "shlex.quote",
  ].map((p) => ({ language: "python", pattern: p, category: "encoding" })),
  ...["parameterize", "cursor.execute(", "sqlalchemy",
    "Django ORM", "Model.objects", "queryset",
  ].map((p) => ({ language: "python", pattern: p, category: "parameterization" })),
  ...["os.path.basename", "secure_filename", "werkzeug.utils.secure_filename",
    "int(", "float(", "str.strip",
    "bcrypt.hashpw", "hashlib.sha256", "secrets.",
  ].map((p) => ({ language: "python", pattern: p, category: "validation" })),
  // Java
  ...["PreparedStatement", "setParameter", "setString", "setInt"].map((p) => ({ language: "java", pattern: p, category: "parameterization" })),
  ...["StringEscapeUtils.escapeHtml", "HtmlUtils.htmlEscape",
    "ESAPI.encoder", "OWASP.encode", "sanitize(",
  ].map((p) => ({ language: "java", pattern: p, category: "encoding" })),
  ...["Integer.parseInt", "Long.parseLong", "UUID.fromString",
    "Paths.get(", "Path.normalize(", "FilenameUtils.getName",
    "BCrypt.hashpw", "MessageDigest.getInstance(\"SHA-256\")",
    "Pattern.compile", "Whitelist.", "Jsoup.clean",
  ].map((p) => ({ language: "java", pattern: p, category: "validation" })),
  // PHP
  ...["htmlspecialchars(", "htmlentities(", "strip_tags("].map((p) => ({ language: "php", pattern: p, category: "encoding" })),
  ...["mysqli_real_escape_string", "PDO::quote", "pg_escape_string"].map((p) => ({ language: "php", pattern: p, category: "parameterization" })),
  ...["intval(", "floatval(", "filter_var(", "FILTER_SANITIZE",
    "basename(", "realpath(", "escapeshellarg(", "escapeshellcmd(",
    "password_hash(", "hash('sha256'",
  ].map((p) => ({ language: "php", pattern: p, category: "validation" })),
  // C#
  ...["HttpUtility.HtmlEncode", "WebUtility.HtmlEncode", "AntiXssEncoder"].map((p) => ({ language: "csharp", pattern: p, category: "encoding" })),
  ...["SqlParameter", "Parameters.AddWithValue", "FromSqlInterpolated"].map((p) => ({ language: "csharp", pattern: p, category: "parameterization" })),
  ...["int.Parse", "Guid.Parse", "Path.GetFileName",
    "BCrypt.Net", "SHA256.Create", "RandomNumberGenerator",
    "HtmlSanitizer", "JavaScriptEncoder",
  ].map((p) => ({ language: "csharp", pattern: p, category: "validation" })),
  // Ruby
  ...["sanitize(", "h(", "html_escape(", "CGI.escapeHTML"].map((p) => ({ language: "ruby", pattern: p, category: "encoding" })),
  ...["ActiveRecord", "where(", "find_by(", "sanitize_sql"].map((p) => ({ language: "ruby", pattern: p, category: "parameterization" })),
  ...["Shellwords.escape", "Integer(", "File.basename(",
    "BCrypt::Password.create", "Digest::SHA256",
  ].map((p) => ({ language: "ruby", pattern: p, category: "validation" })),
  // Go
  ...["template.HTMLEscapeString", "html.EscapeString", "template.HTML("].map((p) => ({ language: "go", pattern: p, category: "encoding" })),
  ...["db.Query(", "db.Exec(", "sqlx.", "gorm."].map((p) => ({ language: "go", pattern: p, category: "parameterization" })),
  ...["strconv.Atoi", "filepath.Base(", "filepath.Clean(",
    "bcrypt.GenerateFromPassword", "sha256.Sum256", "url.QueryEscape",
  ].map((p) => ({ language: "go", pattern: p, category: "validation" })),
  // ABAP / SAP
  ...["cl_abap_dyn_prg=>escape_quotes", "cl_abap_dyn_prg=>check_table_or_view_name_str",
    "cl_abap_dyn_prg=>check_column_name", "escape(",
  ].map((p) => ({ language: "abap", pattern: p, category: "encoding" })),
  ...["AUTHORITY-CHECK", "INTO TABLE", "UP TO", "cl_abap_typedescr=>",
  ].map((p) => ({ language: "abap", pattern: p, category: "validation" })),
  // Generic
  ...["escape", "sanitize", "encode", "parameterize",
    "parseInt", "toInt", "basename", "normalize",
  ].map((p) => ({ language: "*", pattern: p, category: "general" })),
];

// ==================== TAINT SINKS ====================
const TAINT_SINKS: { language: string; pattern: string; cwe: string; category: string; severity: string; owasp2021: string }[] = [
  // JavaScript / TypeScript
  { language: "javascript", pattern: "eval\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "new\\s+Function\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "setTimeout\\s*\\(\\s*[a-zA-Z]", cwe: "CWE-94", category: "Code Injection", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "setInterval\\s*\\(\\s*[a-zA-Z]", cwe: "CWE-94", category: "Code Injection", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "exec\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "execSync\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "spawn\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "child_process", cwe: "CWE-78", category: "OS Command Injection", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "innerHTML\\s*=", cwe: "CWE-79", category: "Cross-Site Scripting", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "outerHTML\\s*=", cwe: "CWE-79", category: "Cross-Site Scripting", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "document\\.write\\s*\\(", cwe: "CWE-79", category: "Cross-Site Scripting", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "insertAdjacentHTML\\s*\\(", cwe: "CWE-79", category: "Cross-Site Scripting", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "dangerouslySetInnerHTML", cwe: "CWE-79", category: "Cross-Site Scripting", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "\\$\\(.*\\)\\.html\\s*\\(", cwe: "CWE-79", category: "Cross-Site Scripting", severity: "HIGH", owasp2021: "A03:2021" },
  // jQuery objects held in $-prefixed variables (`$region.html($msg)`) — the
  // variable naming convention for cached jQuery collections.
  { language: "javascript", pattern: "\\$[A-Za-z_$][\\w$]*\\s*\\.\\s*(?:html|append|prepend|after|before|replaceWith)\\s*\\(", cwe: "CWE-79", category: "Cross-Site Scripting", severity: "HIGH", owasp2021: "A03:2021" },
  // jQuery selector injection: `$(taintedSelector)` — pre-3.0 jQuery parses
  // `#<img onerror>` selector strings as HTML (CVE-2018-14040/1/2, 20676/7).
  // Only the BARE safe idioms `$(document)` / `$(window)` / `$(this)` are
  // excluded. Narrowing to HTML-literal args was tried and REVERTED — it kills
  // exactly this CVE class; the bootstrap FP came from instance-export seeding,
  // not from this sink.
  { language: "javascript", pattern: "\\$\\s*\\(\\s*(?!document\\s*\\)|window\\s*\\)|this\\s*\\))[A-Za-z_$]", cwe: "CWE-79", category: "Cross-Site Scripting", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "query\\s*\\(\\s*[`'\"]\\s*SELECT", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "query\\s*\\(\\s*[`'\"]\\s*INSERT", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "query\\s*\\(\\s*[`'\"]\\s*UPDATE", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "query\\s*\\(\\s*[`'\"]\\s*DELETE", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "execute\\s*\\(\\s*[`'\"].*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "readFile(Sync)?\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "createReadStream\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "unlink(Sync)?\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "writeFile(Sync)?\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "MEDIUM", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "createWriteStream\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "mkdirp\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "MEDIUM", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "(?<!\\w)mkdir(Sync)?\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "MEDIUM", owasp2021: "A01:2021" },
  // path.join/resolve build a filesystem path from their arguments: a tainted
  // non-literal argument is traversal even before the path reaches an fs call
  // (zip-slip and static-server flows). The taint engine only flags when a
  // tainted variable reaches the arguments; confinement guards apply.
  { language: "javascript", pattern: "path\\s*\\.\\s*(join|resolve)\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "MEDIUM", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "fetch\\s*\\(", cwe: "CWE-918", category: "Server-Side Request Forgery", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "javascript", pattern: "axios\\.(get|post|put|delete)\\s*\\(", cwe: "CWE-918", category: "Server-Side Request Forgery", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "javascript", pattern: "http\\.request\\s*\\(", cwe: "CWE-918", category: "Server-Side Request Forgery", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "javascript", pattern: "redirect\\s*\\(", cwe: "CWE-601", category: "Open Redirect", severity: "MEDIUM", owasp2021: "A01:2021" },
  // Reflected/stored XSS: HTTP response writers with tainted data (Express
  // sends strings as text/html).
  { language: "javascript", pattern: "(?:res|response)\\.(?:send|write|end)\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  // DOM-XSS sinks: raw HTML injection points.
  { language: "javascript", pattern: "dangerouslySetInnerHTML", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "\\.html\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "MEDIUM", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "(?:location|document\\.location|window\\.location)\\s*\\.\\s*href\\s*=", cwe: "CWE-79", category: "XSS", severity: "MEDIUM", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "window\\.open\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "MEDIUM", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "importScripts\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "MEDIUM", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "execCommand\\s*\\(\\s*['\"]inserthtml", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  // Code injection: dynamic code construction.
  { language: "javascript", pattern: "new\\s+Function\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "\\bvm\\.runIn(?:New|This)?Context\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  // Path traversal: more filesystem entry points + the send() static-server idiom.
  { language: "javascript", pattern: "(?<!\\w)openSync\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "MEDIUM", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "(?<!\\w)existsSync\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "LOW", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "(?<!\\w)rimraf\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "MEDIUM", owasp2021: "A01:2021" },
  { language: "javascript", pattern: "(?<!\\w)send\\s*\\(\\s*req", cwe: "CWE-22", category: "Path Traversal", severity: "MEDIUM", owasp2021: "A01:2021" },
  // Open redirect via raw Location header.
  { language: "javascript", pattern: "setHeader\\s*\\(\\s*['\"]location", cwe: "CWE-601", category: "Open Redirect", severity: "MEDIUM", owasp2021: "A01:2021" },
  // NoSQL injection: object-built queries with tainted values.
  { language: "javascript", pattern: "\\.findOne\\s*\\(\\s*\\{", cwe: "CWE-89", category: "SQL Injection", severity: "HIGH", owasp2021: "A03:2021" },
  // SSRF: navigation/socket-connect with tainted URLs or hosts.
  { language: "javascript", pattern: "\\.navigate\\s*\\(", cwe: "CWE-918", category: "Server-Side Request Forgery", severity: "MEDIUM", owasp2021: "A10:2021" },
  { language: "javascript", pattern: "\\.connect\\s*\\(\\s*\\{", cwe: "CWE-918", category: "Server-Side Request Forgery", severity: "MEDIUM", owasp2021: "A10:2021" },
  { language: "javascript", pattern: "deserialize\\s*\\(", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "javascript", pattern: "unserialize\\s*\\(", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "javascript", pattern: "node-serialize", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "javascript", pattern: "createCipher\\s*\\(", cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021" },
  { language: "javascript", pattern: "createHash\\s*\\(\\s*['\"]md5['\"]", cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021" },
  { language: "javascript", pattern: "createHash\\s*\\(\\s*['\"]sha1['\"]", cwe: "CWE-327", category: "Broken Crypto", severity: "LOW", owasp2021: "A02:2021" },
  { language: "javascript", pattern: "Math\\.random\\s*\\(", cwe: "CWE-338", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021" },
  // Python
  { language: "python", pattern: "eval\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "python", pattern: "exec\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "python", pattern: "compile\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "python", pattern: "os\\.system\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "python", pattern: "os\\.popen\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "python", pattern: "subprocess\\.(call|run|Popen)\\s*\\(.*shell\\s*=\\s*True", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "python", pattern: "commands\\.getoutput\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "python", pattern: "cursor\\.execute\\s*\\(.*%|cursor\\.execute\\s*\\(.*\\.format|cursor\\.execute\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "python", pattern: "raw\\s*\\(.*%|raw\\s*\\(.*\\.format|raw\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "python", pattern: "open\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "python", pattern: "os\\.path\\.join\\s*\\(.*request", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "python", pattern: "send_file\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "python", pattern: "pickle\\.loads?\\s*\\(", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "python", pattern: "yaml\\.load\\s*\\((?!.*Loader)", cwe: "CWE-502", category: "Insecure Deserialization", severity: "HIGH", owasp2021: "A08:2021" },
  { language: "python", pattern: "marshal\\.loads?\\s*\\(", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "python", pattern: "requests\\.(get|post|put)\\s*\\(", cwe: "CWE-918", category: "SSRF", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "python", pattern: "urllib\\.request\\.urlopen\\s*\\(", cwe: "CWE-918", category: "SSRF", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "python", pattern: "render_template_string\\s*\\(", cwe: "CWE-1336", category: "SSTI", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "python", pattern: "hashlib\\.md5\\s*\\(", cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021" },
  { language: "python", pattern: "random\\.(random|randint|choice)\\s*\\(", cwe: "CWE-338", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021" },
  // Java
  { language: "java", pattern: "Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "java", pattern: "ProcessBuilder\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "java", pattern: "Statement\\.execute(Query|Update)?\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "java", pattern: "createQuery\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "java", pattern: "createNativeQuery\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "java", pattern: "getWriter\\(\\)\\.print(ln)?\\s*\\(.*request", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "java", pattern: "setAttribute\\s*\\(.*request\\.getParameter", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "java", pattern: "ObjectInputStream.*readObject\\s*\\(", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "java", pattern: "XMLDecoder.*readObject\\s*\\(", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "java", pattern: "new\\s+File\\s*\\(.*request", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "java", pattern: "FileInputStream\\s*\\(.*request", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "java", pattern: "URL\\s*\\(.*request", cwe: "CWE-918", category: "SSRF", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "java", pattern: "HttpURLConnection.*request", cwe: "CWE-918", category: "SSRF", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "java", pattern: "sendRedirect\\s*\\(.*request", cwe: "CWE-601", category: "Open Redirect", severity: "MEDIUM", owasp2021: "A01:2021" },
  { language: "java", pattern: "ScriptEngine.*eval\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "java", pattern: "Cipher\\.getInstance\\s*\\(\\s*\"(DES|RC4|Blowfish)", cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021" },
  { language: "java", pattern: "MessageDigest\\.getInstance\\s*\\(\\s*\"(MD5|SHA-1)\"", cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021" },
  // Java — taint-confirmed sinks (general form). Unlike the `.*request` variants
  // above (which need the request inline), these fire only when a *tainted
  // variable* reaches the call, so they catch realistic source→propagation→sink
  // flows (e.g. cookie → param → fileName → new File(fileName)) without adding
  // false positives on static arguments.
  { language: "java", pattern: "new\\s+(?:java\\.io\\.)?File\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "java", pattern: "new\\s+(?:java\\.io\\.)?FileInputStream\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "java", pattern: "new\\s+(?:java\\.io\\.)?FileOutputStream\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "java", pattern: "new\\s+(?:java\\.io\\.)?RandomAccessFile\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "java", pattern: "new\\s+(?:java\\.net\\.)?URI\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "java", pattern: "Files\\.(newInputStream|newOutputStream|read|write|copy|move|delete)\\s*\\(", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "java", pattern: "\\.exec\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "java", pattern: "(executeQuery|executeUpdate|executeBatch|prepareStatement|prepareCall)\\s*\\(", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "java", pattern: "\\.execute\\s*\\(", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "java", pattern: "queryFor(?:Object|Long|Int|String|List|Map|Row|RowSet)\\s*\\(|JDBCtemplate\\s*\\.\\s*(?:query|update)\\s*\\(", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "java", pattern: "\\.print(ln)?\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "java", pattern: "\\.format\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "java", pattern: "\\.printf\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "java", pattern: "getWriter\\(\\)\\s*\\.\\s*write\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "java", pattern: "new\\s+(?:java\\.net\\.)?URL\\s*\\(", cwe: "CWE-918", category: "SSRF", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "java", pattern: "\\.search\\s*\\(", cwe: "CWE-90", category: "LDAP Injection", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "java", pattern: "(XPath\\.evaluate|xpath\\.evaluate|\\.compile)\\s*\\(", cwe: "CWE-643", category: "XPath Injection", severity: "HIGH", owasp2021: "A03:2021" },
  // PHP
  { language: "php", pattern: "eval\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "assert\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "preg_replace\\s*\\(.*/e", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "system\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "exec\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "passthru\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "shell_exec\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "popen\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "proc_open\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "mysql_query\\s*\\(.*\\$", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "mysqli_query\\s*\\(.*\\$", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "->query\\s*\\(.*\\$", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "include\\s*\\(.*\\$", cwe: "CWE-98", category: "Remote File Inclusion", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "require\\s*\\(.*\\$", cwe: "CWE-98", category: "Remote File Inclusion", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "php", pattern: "unserialize\\s*\\(", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "php", pattern: "file_get_contents\\s*\\(.*\\$", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "php", pattern: "fopen\\s*\\(.*\\$", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "php", pattern: "header\\s*\\(\\s*['\"]Location.*\\$", cwe: "CWE-601", category: "Open Redirect", severity: "MEDIUM", owasp2021: "A01:2021" },
  { language: "php", pattern: "md5\\s*\\(", cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021" },
  { language: "php", pattern: "sha1\\s*\\(", cwe: "CWE-327", category: "Broken Crypto", severity: "LOW", owasp2021: "A02:2021" },
  // C#
  { language: "csharp", pattern: "Process\\.Start\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "csharp", pattern: "cmd\\.exe|/bin/sh|/bin/bash", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "csharp", pattern: "ExecuteNonQuery\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "csharp", pattern: "ExecuteReader\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "csharp", pattern: "FromSqlRaw\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "csharp", pattern: "Response\\.Write\\s*\\(.*Request", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "csharp", pattern: "Html\\.Raw\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "csharp", pattern: "BinaryFormatter.*Deserialize\\s*\\(", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "csharp", pattern: "JsonConvert\\.Deserialize.*TypeNameHandling", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "csharp", pattern: "File\\.(ReadAll|WriteAll|Open)\\s*\\(.*Request", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "csharp", pattern: "Redirect\\s*\\(.*Request", cwe: "CWE-601", category: "Open Redirect", severity: "MEDIUM", owasp2021: "A01:2021" },
  { language: "csharp", pattern: "HttpClient.*Request", cwe: "CWE-918", category: "SSRF", severity: "HIGH", owasp2021: "A10:2021" },
  // Ruby
  { language: "ruby", pattern: "eval\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "instance_eval\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "class_eval\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "system\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "exec\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "`.*\\#", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "IO\\.popen\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "Open3\\.", cwe: "CWE-78", category: "OS Command Injection", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "execute\\s*\\(.*\\#", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "where\\s*\\(\\s*['\"].*\\#", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "ruby", pattern: "Marshal\\.load\\s*\\(", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "ruby", pattern: "YAML\\.load\\s*\\((?!.*safe)", cwe: "CWE-502", category: "Insecure Deserialization", severity: "HIGH", owasp2021: "A08:2021" },
  { language: "ruby", pattern: "File\\.(open|read|write)\\s*\\(.*params", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "ruby", pattern: "send_file\\s*\\(.*params", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "ruby", pattern: "redirect_to\\s*\\(.*params", cwe: "CWE-601", category: "Open Redirect", severity: "MEDIUM", owasp2021: "A01:2021" },
  // Go
  { language: "go", pattern: "exec\\.Command\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "go", pattern: "os\\.StartProcess\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "go", pattern: "db\\.(Query|Exec)\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "go", pattern: "fmt\\.Sprintf\\s*\\(.*SELECT.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "go", pattern: "w\\.Write\\s*\\(.*r\\.", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "go", pattern: "template\\.HTML\\s*\\(", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "go", pattern: "os\\.Open\\s*\\(.*r\\.", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "go", pattern: "ioutil\\.ReadFile\\s*\\(.*r\\.", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "go", pattern: "http\\.Get\\s*\\(.*r\\.", cwe: "CWE-918", category: "SSRF", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "go", pattern: "http\\.Redirect\\s*\\(.*r\\.", cwe: "CWE-601", category: "Open Redirect", severity: "MEDIUM", owasp2021: "A01:2021" },
  // ABAP / SAP
  { language: "abap", pattern: "EXECUTE\\s+REPORT|GENERATE\\s+SUBROUTINE|INSERT\\s+REPORT", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "abap", pattern: "EXEC\\s+SQL", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "abap", pattern: "SELECT\\s+.*\\bWHERE\\b.*\\+\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "abap", pattern: "CALL\\s+'SYSTEM'|CALL\\s+SYSTEM", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "abap", pattern: "OPEN\\s+DATASET", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  { language: "abap", pattern: "cl_http_client=>create_by_url", cwe: "CWE-918", category: "SSRF", severity: "HIGH", owasp2021: "A10:2021" },
  { language: "abap", pattern: "CONCATENATE\\s+.*INTO\\s+.*where", cwe: "CWE-89", category: "SQL Injection", severity: "HIGH", owasp2021: "A03:2021" },
  // Generic (covers remaining 12+ languages)
  { language: "*", pattern: "eval\\s*\\(", cwe: "CWE-94", category: "Code Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "*", pattern: "exec\\s*\\(|system\\s*\\(|popen\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "*", pattern: "query\\s*\\(.*\\+|execute\\s*\\(.*\\+", cwe: "CWE-89", category: "SQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "*", pattern: "innerHTML|document\\.write", cwe: "CWE-79", category: "XSS", severity: "HIGH", owasp2021: "A03:2021" },
  { language: "*", pattern: "deserialize|unserialize|readObject", cwe: "CWE-502", category: "Insecure Deserialization", severity: "CRITICAL", owasp2021: "A08:2021" },
  { language: "*", pattern: "fopen|open\\s*\\(|readFile", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
];

// ==================== SECRET PATTERNS ====================
const SECRET_PATTERNS: { ruleId: string; name: string; regex: string; severity: string; cwe: string; description: string }[] = [
  { ruleId: "aws-access-key", name: "AWS Access Key ID", regex: "AKIA[0-9A-Z]{16}", severity: "CRITICAL", cwe: "CWE-798", description: "AWS Access Key ID detected" },
  { ruleId: "aws-secret-key", name: "AWS Secret Access Key", regex: "(?i)aws_secret_access_key\\s*[=:]\\s*[A-Za-z0-9/+=]{40}", severity: "CRITICAL", cwe: "CWE-798", description: "AWS Secret Access Key detected" },
  { ruleId: "aws-mws-key", name: "AWS MWS Auth Token", regex: "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", severity: "CRITICAL", cwe: "CWE-798", description: "AWS MWS Auth Token detected" },
  { ruleId: "github-pat", name: "GitHub Personal Access Token", regex: "ghp_[A-Za-z0-9]{36}", severity: "CRITICAL", cwe: "CWE-798", description: "GitHub Personal Access Token detected" },
  { ruleId: "github-oauth", name: "GitHub OAuth Token", regex: "gho_[A-Za-z0-9]{36}", severity: "CRITICAL", cwe: "CWE-798", description: "GitHub OAuth Token detected" },
  { ruleId: "github-app-token", name: "GitHub App Token", regex: "(?:ghu|ghs)_[A-Za-z0-9]{36}", severity: "CRITICAL", cwe: "CWE-798", description: "GitHub App Token detected" },
  { ruleId: "github-refresh", name: "GitHub Refresh Token", regex: "ghr_[A-Za-z0-9]{36}", severity: "CRITICAL", cwe: "CWE-798", description: "GitHub Refresh Token detected" },
  { ruleId: "github-fine-grained", name: "GitHub Fine-Grained PAT", regex: "github_pat_[A-Za-z0-9_]{82}", severity: "CRITICAL", cwe: "CWE-798", description: "GitHub Fine-Grained PAT detected" },
  { ruleId: "gcp-api-key", name: "Google Cloud API Key", regex: "AIza[0-9A-Za-z\\-_]{35}", severity: "CRITICAL", cwe: "CWE-798", description: "Google Cloud API Key detected" },
  { ruleId: "gcp-service-account", name: "GCP Service Account", regex: "\"type\":\\s*\"service_account\"", severity: "HIGH", cwe: "CWE-798", description: "GCP Service Account JSON detected" },
  { ruleId: "firebase-url", name: "Firebase Database URL", regex: "https://[a-z0-9-]+\\.firebaseio\\.com", severity: "HIGH", cwe: "CWE-798", description: "Firebase Database URL detected" },
  { ruleId: "slack-bot-token", name: "Slack Bot Token", regex: "xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", severity: "CRITICAL", cwe: "CWE-798", description: "Slack Bot Token detected" },
  { ruleId: "slack-user-token", name: "Slack User Token", regex: "xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}", severity: "CRITICAL", cwe: "CWE-798", description: "Slack User Token detected" },
  { ruleId: "slack-webhook", name: "Slack Webhook URL", regex: "https://hooks\\.slack\\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}", severity: "HIGH", cwe: "CWE-798", description: "Slack Webhook URL detected" },
  { ruleId: "stripe-secret", name: "Stripe Secret Key", regex: "sk_live_[0-9a-zA-Z]{24,}", severity: "CRITICAL", cwe: "CWE-798", description: "Stripe Secret Key detected" },
  { ruleId: "stripe-publishable", name: "Stripe Publishable Key", regex: "pk_live_[0-9a-zA-Z]{24,}", severity: "MEDIUM", cwe: "CWE-798", description: "Stripe Publishable Key detected" },
  { ruleId: "stripe-restricted", name: "Stripe Restricted Key", regex: "rk_live_[0-9a-zA-Z]{24,}", severity: "CRITICAL", cwe: "CWE-798", description: "Stripe Restricted Key detected" },
  { ruleId: "private-key-rsa", name: "RSA Private Key", regex: "-----BEGIN RSA PRIVATE KEY-----", severity: "CRITICAL", cwe: "CWE-321", description: "RSA Private Key detected" },
  { ruleId: "private-key-ec", name: "EC Private Key", regex: "-----BEGIN EC PRIVATE KEY-----", severity: "CRITICAL", cwe: "CWE-321", description: "EC Private Key detected" },
  { ruleId: "private-key-dsa", name: "DSA Private Key", regex: "-----BEGIN DSA PRIVATE KEY-----", severity: "CRITICAL", cwe: "CWE-321", description: "DSA Private Key detected" },
  { ruleId: "private-key-generic", name: "Private Key", regex: "-----BEGIN PRIVATE KEY-----", severity: "CRITICAL", cwe: "CWE-321", description: "Private Key detected" },
  { ruleId: "private-key-openssh", name: "OpenSSH Private Key", regex: "-----BEGIN OPENSSH PRIVATE KEY-----", severity: "CRITICAL", cwe: "CWE-321", description: "OpenSSH Private Key detected" },
  { ruleId: "private-key-pgp", name: "PGP Private Key", regex: "-----BEGIN PGP PRIVATE KEY BLOCK-----", severity: "CRITICAL", cwe: "CWE-321", description: "PGP Private Key detected" },
  { ruleId: "jwt-token", name: "JSON Web Token", regex: "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}", severity: "HIGH", cwe: "CWE-798", description: "Hardcoded JWT token detected" },
  { ruleId: "generic-password", name: "Hardcoded Password", regex: "(?i)(?:password|passwd|pwd)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]", severity: "HIGH", cwe: "CWE-798", description: "Hardcoded password detected" },
  { ruleId: "generic-secret", name: "Hardcoded Secret", regex: "(?i)(?:secret|api_secret|client_secret)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]", severity: "HIGH", cwe: "CWE-798", description: "Hardcoded secret detected" },
  { ruleId: "generic-api-key", name: "Hardcoded API Key", regex: "(?i)(?:api_key|apikey|api-key)\\s*[=:]\\s*['\"][^'\"]{16,}['\"]", severity: "HIGH", cwe: "CWE-798", description: "Hardcoded API key detected" },
  { ruleId: "generic-token", name: "Hardcoded Token", regex: "(?i)(?:access_token|auth_token|token)\\s*[=:]\\s*['\"][^'\"]{16,}['\"]", severity: "HIGH", cwe: "CWE-798", description: "Hardcoded token detected" },
  { ruleId: "generic-connection-string", name: "Connection String", regex: "(?i)(?:mongodb|postgres|mysql|redis|amqp)(?:\\+srv)?://[^\\s'\"]{10,}", severity: "CRITICAL", cwe: "CWE-798", description: "Database connection string with credentials detected" },
  { ruleId: "azure-storage-key", name: "Azure Storage Key", regex: "(?i)AccountKey=[A-Za-z0-9+/=]{88}", severity: "CRITICAL", cwe: "CWE-798", description: "Azure Storage Account Key detected" },
  { ruleId: "azure-ad-client-secret", name: "Azure AD Client Secret", regex: "(?i)client_secret\\s*[=:]\\s*[A-Za-z0-9~._-]{34}", severity: "CRITICAL", cwe: "CWE-798", description: "Azure AD Client Secret detected" },
  { ruleId: "heroku-api-key", name: "Heroku API Key", regex: "(?i)heroku[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", severity: "HIGH", cwe: "CWE-798", description: "Heroku API Key detected" },
  { ruleId: "digitalocean-token", name: "DigitalOcean Token", regex: "dop_v1_[a-f0-9]{64}", severity: "CRITICAL", cwe: "CWE-798", description: "DigitalOcean API Token detected" },
  { ruleId: "twilio-api-key", name: "Twilio API Key", regex: "SK[0-9a-fA-F]{32}", severity: "HIGH", cwe: "CWE-798", description: "Twilio API Key detected" },
  { ruleId: "sendgrid-api-key", name: "SendGrid API Key", regex: "SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}", severity: "HIGH", cwe: "CWE-798", description: "SendGrid API Key detected" },
  { ruleId: "mailgun-api-key", name: "Mailgun API Key", regex: "key-[0-9a-zA-Z]{32}", severity: "HIGH", cwe: "CWE-798", description: "Mailgun API Key detected" },
  { ruleId: "npm-token", name: "NPM Access Token", regex: "//registry\\.npmjs\\.org/:_authToken=[a-f0-9-]{36}", severity: "HIGH", cwe: "CWE-798", description: "NPM Access Token detected" },
  { ruleId: "pypi-token", name: "PyPI Token", regex: "pypi-[A-Za-z0-9_-]{50,}", severity: "HIGH", cwe: "CWE-798", description: "PyPI API Token detected" },
  { ruleId: "shopify-token", name: "Shopify Token", regex: "shpat_[a-fA-F0-9]{32}", severity: "HIGH", cwe: "CWE-798", description: "Shopify Access Token detected" },
  { ruleId: "square-token", name: "Square Access Token", regex: "sq0atp-[0-9A-Za-z\\-_]{22}", severity: "HIGH", cwe: "CWE-798", description: "Square Access Token detected" },
  { ruleId: "paypal-braintree", name: "PayPal Braintree Token", regex: "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}", severity: "HIGH", cwe: "CWE-798", description: "PayPal Braintree Token detected" },
  { ruleId: "basic-auth-header", name: "Basic Auth in Code", regex: "(?i)authorization:\\s*['\"]Basic\\s+[A-Za-z0-9+/=]{10,}['\"]", severity: "HIGH", cwe: "CWE-798", description: "Basic Auth credentials in code" },
  { ruleId: "bearer-token-hardcoded", name: "Hardcoded Bearer Token", regex: "(?i)bearer\\s+[A-Za-z0-9._-]{20,}", severity: "HIGH", cwe: "CWE-798", description: "Hardcoded Bearer token detected" },
  { ruleId: "ssh-password", name: "SSH Password", regex: "(?i)sshpass\\s+-p\\s+['\"][^'\"]+['\"]", severity: "CRITICAL", cwe: "CWE-798", description: "SSH password in command" },
  { ruleId: "encryption-key-hex", name: "Hardcoded Encryption Key", regex: "(?i)(?:encryption_key|aes_key|secret_key)\\s*[=:]\\s*['\"][0-9a-fA-F]{32,}['\"]", severity: "HIGH", cwe: "CWE-321", description: "Hardcoded encryption key detected" },
  { ruleId: "webhook-secret", name: "Webhook Secret", regex: "(?i)webhook_secret\\s*[=:]\\s*['\"][^'\"]{16,}['\"]", severity: "MEDIUM", cwe: "CWE-798", description: "Webhook secret detected" },
];

// ==================== IaC RULES ====================
const IAC_RULES: { ruleId: string; name: string; pattern: string; severity: string; cwe: string; category: string; description: string; fileTypes: string[]; framework: string }[] = [
  // Terraform (CIS AWS)
  { ruleId: "tf-sg-open-ingress", name: "Security Group allows ingress from 0.0.0.0/0", pattern: "cidr_blocks\\s*=\\s*\\[\\s*\"0\\.0\\.0\\.0/0\"", severity: "HIGH", cwe: "CWE-284", category: "Network Exposure", description: "Security group rule allows inbound traffic from any IP address. Restrict to specific CIDR ranges per CIS AWS 5.2.", fileTypes: [".tf"], framework: "cis" },
  { ruleId: "tf-sg-open-egress", name: "Security Group allows unrestricted egress", pattern: "cidr_blocks\\s*=\\s*\\[\\s*\"0\\.0\\.0\\.0/0\".*egress", severity: "MEDIUM", cwe: "CWE-284", category: "Network Exposure", description: "Unrestricted egress may allow data exfiltration. Restrict outbound rules.", fileTypes: [".tf"], framework: "cis" },
  { ruleId: "tf-s3-public", name: "S3 bucket with public-read ACL", pattern: "acl\\s*=\\s*\"public-read\"", severity: "HIGH", cwe: "CWE-732", category: "Data Exposure", description: "S3 bucket is publicly readable. Use private ACL with IAM policies per CIS AWS 2.1.5.", fileTypes: [".tf"], framework: "cis" },
  { ruleId: "tf-s3-public-rw", name: "S3 bucket with public-read-write ACL", pattern: "acl\\s*=\\s*\"public-read-write\"", severity: "CRITICAL", cwe: "CWE-732", category: "Data Exposure", description: "S3 bucket is publicly writable. This allows anyone to upload/modify data.", fileTypes: [".tf"], framework: "cis" },
  { ruleId: "tf-no-encryption", name: "Resource with encryption explicitly disabled", pattern: "encrypted\\s*=\\s*false", severity: "HIGH", cwe: "CWE-311", category: "Missing Encryption", description: "Encryption is disabled. Enable encryption at rest per CIS AWS 2.2.1.", fileTypes: [".tf"], framework: "cis" },
  { ruleId: "tf-no-logging", name: "Logging explicitly disabled", pattern: "enable_logging\\s*=\\s*false", severity: "MEDIUM", cwe: "CWE-778", category: "Insufficient Logging", description: "Logging is disabled. Enable audit logging for compliance per NIST AU-2.", fileTypes: [".tf"], framework: "nist" },
  { ruleId: "tf-rds-public", name: "RDS instance publicly accessible", pattern: "publicly_accessible\\s*=\\s*true", severity: "HIGH", cwe: "CWE-284", category: "Network Exposure", description: "Database is publicly accessible from the internet. Set publicly_accessible = false.", fileTypes: [".tf"], framework: "cis" },
  { ruleId: "tf-iam-wildcard", name: "IAM policy with wildcard actions", pattern: "actions\\s*=\\s*\\[\\s*\"\\*\"\\s*\\]", severity: "HIGH", cwe: "CWE-269", category: "Excessive Permissions", description: "IAM policy grants all actions (*). Apply least privilege per CIS AWS 1.16.", fileTypes: [".tf"], framework: "cis" },
  { ruleId: "tf-iam-wildcard-resource", name: "IAM policy with wildcard resources", pattern: "resources\\s*=\\s*\\[\\s*\"\\*\"\\s*\\]", severity: "MEDIUM", cwe: "CWE-269", category: "Excessive Permissions", description: "IAM policy applies to all resources (*). Scope to specific resource ARNs.", fileTypes: [".tf"], framework: "cis" },
  { ruleId: "tf-http-only", name: "Load balancer using HTTP (no TLS)", pattern: "listener.*protocol\\s*=\\s*\"HTTP\"", severity: "MEDIUM", cwe: "CWE-319", category: "Cleartext Transmission", description: "Traffic is unencrypted. Use HTTPS/TLS per CIS AWS 2.3.1.", fileTypes: [".tf"], framework: "cis" },
  { ruleId: "tf-no-versioning", name: "S3 versioning disabled", pattern: "versioning.*enabled\\s*=\\s*false", severity: "LOW", cwe: "CWE-778", category: "Data Protection", description: "Versioning not enabled. Enable for data recovery per CIS AWS 2.1.3.", fileTypes: [".tf"], framework: "cis" },
  // Docker (CIS Docker)
  { ruleId: "docker-user-root", name: "Container runs as root user", pattern: "^USER\\s+root", severity: "HIGH", cwe: "CWE-250", category: "Privilege Escalation", description: "Container explicitly runs as root. Use a non-root user per CIS Docker 4.1.", fileTypes: ["Dockerfile", ".dockerfile"], framework: "cis" },
  { ruleId: "docker-add-not-copy", name: "ADD used instead of COPY", pattern: "^ADD\\s+(?!.*--chown)", severity: "LOW", cwe: "CWE-668", category: "Best Practice", description: "ADD has implicit behaviors (URL fetch, tar extraction). Prefer COPY per CIS Docker 4.9.", fileTypes: ["Dockerfile", ".dockerfile"], framework: "cis" },
  { ruleId: "docker-secret-env", name: "Secret stored in ENV instruction", pattern: "^ENV\\s+.*(PASSWORD|SECRET|TOKEN|KEY|API_KEY)\\s*=", severity: "HIGH", cwe: "CWE-798", category: "Hardcoded Secret", description: "Secrets in ENV are visible in image metadata. Use Docker secrets or runtime injection per CIS Docker 5.10.", fileTypes: ["Dockerfile", ".dockerfile"], framework: "cis" },
  { ruleId: "docker-latest-tag", name: "Base image uses :latest tag", pattern: "^FROM\\s+\\S+:latest", severity: "MEDIUM", cwe: "CWE-1104", category: "Supply Chain", description: "Using :latest makes builds non-reproducible. Pin to a specific version per CIS Docker 4.2.", fileTypes: ["Dockerfile", ".dockerfile"], framework: "cis" },
  { ruleId: "docker-curl-pipe-sh", name: "Piping curl to shell", pattern: "curl.*\\|\\s*(?:ba)?sh", severity: "HIGH", cwe: "CWE-494", category: "Supply Chain", description: "Downloading and executing remote code without verification. Verify checksums first.", fileTypes: ["Dockerfile", ".dockerfile"], framework: "cis" },
  { ruleId: "docker-wget-pipe-sh", name: "Piping wget to shell", pattern: "wget.*\\|\\s*(?:ba)?sh", severity: "HIGH", cwe: "CWE-494", category: "Supply Chain", description: "Downloading and executing remote code without verification.", fileTypes: ["Dockerfile", ".dockerfile"], framework: "cis" },
  { ruleId: "docker-expose-ssh", name: "SSH port exposed in container", pattern: "^EXPOSE\\s+22", severity: "MEDIUM", cwe: "CWE-284", category: "Network Exposure", description: "Containers should not run SSH. Use docker exec or kubectl exec instead.", fileTypes: ["Dockerfile", ".dockerfile"], framework: "cis" },
  // Kubernetes (CIS K8s)
  { ruleId: "k8s-privileged", name: "Privileged container", pattern: "privileged:\\s*true", severity: "CRITICAL", cwe: "CWE-250", category: "Privilege Escalation", description: "Container runs in privileged mode with full host access. Disable per CIS K8s 5.2.1.", fileTypes: [".yaml", ".yml"], framework: "cis" },
  { ruleId: "k8s-host-network", name: "Host network namespace shared", pattern: "hostNetwork:\\s*true", severity: "HIGH", cwe: "CWE-284", category: "Network Exposure", description: "Pod shares host network namespace. Disable per CIS K8s 5.2.4.", fileTypes: [".yaml", ".yml"], framework: "cis" },
  { ruleId: "k8s-host-pid", name: "Host PID namespace shared", pattern: "hostPID:\\s*true", severity: "HIGH", cwe: "CWE-284", category: "Privilege Escalation", description: "Pod shares host PID namespace. Disable per CIS K8s 5.2.2.", fileTypes: [".yaml", ".yml"], framework: "cis" },
  { ruleId: "k8s-allow-privilege-escalation", name: "Privilege escalation allowed", pattern: "allowPrivilegeEscalation:\\s*true", severity: "HIGH", cwe: "CWE-250", category: "Privilege Escalation", description: "Container can gain more privileges than parent. Set to false per CIS K8s 5.2.5.", fileTypes: [".yaml", ".yml"], framework: "cis" },
  { ruleId: "k8s-run-as-root", name: "Container allowed to run as root", pattern: "runAsNonRoot:\\s*false", severity: "HIGH", cwe: "CWE-250", category: "Privilege Escalation", description: "Set runAsNonRoot: true to prevent root execution per CIS K8s 5.2.6.", fileTypes: [".yaml", ".yml"], framework: "cis" },
  { ruleId: "k8s-latest-image", name: "Container image uses :latest tag", pattern: "image:.*:latest", severity: "MEDIUM", cwe: "CWE-1104", category: "Supply Chain", description: "Pin images to specific versions for reproducibility and security.", fileTypes: [".yaml", ".yml"], framework: "cis" },
  { ruleId: "k8s-no-resource-limits", name: "No resource limits defined", pattern: "containers:(?![\\s\\S]*resources:)", severity: "LOW", cwe: "CWE-770", category: "Resource Exhaustion", description: "Without resource limits, a pod can exhaust node resources. Set CPU/memory limits.", fileTypes: [".yaml", ".yml"], framework: "cis" },
  { ruleId: "k8s-read-only-false", name: "Writable root filesystem", pattern: "readOnlyRootFilesystem:\\s*false", severity: "MEDIUM", cwe: "CWE-732", category: "Filesystem Access", description: "Container root filesystem is writable. Set readOnlyRootFilesystem: true.", fileTypes: [".yaml", ".yml"], framework: "cis" },
  // CloudFormation
  { ruleId: "cfn-sg-open", name: "Security Group open to world", pattern: "CidrIp:\\s*0\\.0\\.0\\.0/0", severity: "HIGH", cwe: "CWE-284", category: "Network Exposure", description: "Security group allows traffic from 0.0.0.0/0. Restrict CIDR ranges.", fileTypes: [".yaml", ".yml", ".json"], framework: "aws" },
  { ruleId: "cfn-no-encryption", name: "EBS volume encryption disabled", pattern: "Encrypted:\\s*false", severity: "HIGH", cwe: "CWE-311", category: "Missing Encryption", description: "EBS volume is not encrypted. Enable encryption at rest.", fileTypes: [".yaml", ".yml", ".json"], framework: "aws" },
  { ruleId: "cfn-public-s3", name: "S3 bucket public read access", pattern: "AccessControl:\\s*PublicRead", severity: "HIGH", cwe: "CWE-732", category: "Data Exposure", description: "S3 bucket has PublicRead ACL. Use bucket policies with least privilege.", fileTypes: [".yaml", ".yml", ".json"], framework: "aws" },
];

// ==================== COMPLIANCE MAPPINGS (CWE → Frameworks) ====================
const COMPLIANCE_MAPPINGS: { cwe: string; pciDss: string | null; hipaa: string | null; nist80053: string | null; iso27001: string | null; owasp2021: string | null; owasp2017: string | null; mitreTop25: number | null }[] = [
  { cwe: "CWE-78", pciDss: "6.5.1", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A03:2021", owasp2017: "A1", mitreTop25: 5 },
  { cwe: "CWE-79", pciDss: "6.5.7", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A03:2021", owasp2017: "A7", mitreTop25: 3 },
  { cwe: "CWE-89", pciDss: "6.5.1", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A03:2021", owasp2017: "A1", mitreTop25: 1 },
  { cwe: "CWE-94", pciDss: "6.5.1", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A03:2021", owasp2017: "A1", mitreTop25: 4 },
  { cwe: "CWE-22", pciDss: "6.5.8", hipaa: "164.312(a)(1)", nist80053: "AC-3", iso27001: "A.14.2.5", owasp2021: "A01:2021", owasp2017: "A5", mitreTop25: 8 },
  { cwe: "CWE-98", pciDss: "6.5.1", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A03:2021", owasp2017: "A1", mitreTop25: null },
  { cwe: "CWE-502", pciDss: "6.5.8", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A08:2021", owasp2017: "A8", mitreTop25: 12 },
  { cwe: "CWE-918", pciDss: "6.5.8", hipaa: "164.312(a)(1)", nist80053: "SC-7", iso27001: "A.14.2.5", owasp2021: "A10:2021", owasp2017: "A10", mitreTop25: 10 },
  { cwe: "CWE-601", pciDss: "6.5.8", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A01:2021", owasp2017: "A6", mitreTop25: null },
  { cwe: "CWE-327", pciDss: "3.4", hipaa: "164.312(e)(2)(ii)", nist80053: "SC-13", iso27001: "A.10.1.1", owasp2021: "A02:2021", owasp2017: "A3", mitreTop25: null },
  { cwe: "CWE-338", pciDss: "3.4", hipaa: "164.312(e)(2)(ii)", nist80053: "SC-13", iso27001: "A.10.1.1", owasp2021: "A02:2021", owasp2017: "A3", mitreTop25: null },
  { cwe: "CWE-798", pciDss: "8.2.1", hipaa: "164.312(a)(2)(i)", nist80053: "IA-5", iso27001: "A.9.4.3", owasp2021: "A07:2021", owasp2017: "A2", mitreTop25: 7 },
  { cwe: "CWE-321", pciDss: "3.5.2", hipaa: "164.312(e)(2)(ii)", nist80053: "SC-12", iso27001: "A.10.1.2", owasp2021: "A02:2021", owasp2017: "A3", mitreTop25: null },
  { cwe: "CWE-284", pciDss: "7.1", hipaa: "164.312(a)(1)", nist80053: "AC-3", iso27001: "A.14.1.3", owasp2021: "A01:2021", owasp2017: "A5", mitreTop25: null },
  { cwe: "CWE-732", pciDss: "7.1", hipaa: "164.312(a)(1)", nist80053: "AC-6", iso27001: "A.9.4.1", owasp2021: "A01:2021", owasp2017: "A5", mitreTop25: 9 },
  { cwe: "CWE-311", pciDss: "3.4", hipaa: "164.312(e)(2)(ii)", nist80053: "SC-8", iso27001: "A.10.1.1", owasp2021: "A02:2021", owasp2017: "A3", mitreTop25: null },
  { cwe: "CWE-269", pciDss: "7.1.2", hipaa: "164.312(a)(1)", nist80053: "AC-6", iso27001: "A.9.2.3", owasp2021: "A01:2021", owasp2017: "A5", mitreTop25: null },
  { cwe: "CWE-250", pciDss: "7.1.2", hipaa: "164.312(a)(1)", nist80053: "AC-6", iso27001: "A.9.2.3", owasp2021: "A05:2021", owasp2017: "A5", mitreTop25: null },
  { cwe: "CWE-778", pciDss: "10.2", hipaa: "164.312(b)", nist80053: "AU-2", iso27001: "A.12.4.1", owasp2021: "A09:2021", owasp2017: "A10", mitreTop25: null },
  { cwe: "CWE-319", pciDss: "4.1", hipaa: "164.312(e)(1)", nist80053: "SC-8", iso27001: "A.13.2.1", owasp2021: "A02:2021", owasp2017: "A3", mitreTop25: null },
  { cwe: "CWE-1104", pciDss: "6.3.2", hipaa: null, nist80053: "CM-2", iso27001: "A.14.2.2", owasp2021: "A06:2021", owasp2017: "A9", mitreTop25: null },
  { cwe: "CWE-494", pciDss: "6.3.2", hipaa: null, nist80053: "CM-7", iso27001: "A.14.2.7", owasp2021: "A08:2021", owasp2017: "A8", mitreTop25: null },
  { cwe: "CWE-668", pciDss: "6.5.8", hipaa: "164.312(a)(1)", nist80053: "AC-3", iso27001: "A.14.1.3", owasp2021: "A05:2021", owasp2017: "A5", mitreTop25: null },
  { cwe: "CWE-770", pciDss: "6.5.8", hipaa: null, nist80053: "SC-5", iso27001: "A.12.1.3", owasp2021: "A05:2021", owasp2017: "A5", mitreTop25: null },
  { cwe: "CWE-1336", pciDss: "6.5.1", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A03:2021", owasp2017: "A1", mitreTop25: null },
];

// ==================== SEED FUNCTION ====================
async function main() {
  console.log("[SEED-SECURITY] Starting security rules seed...");

  // 1. Taint Sources
  console.log(`[SEED-SECURITY] Seeding ${TAINT_SOURCES.length} taint sources...`);
  for (const src of TAINT_SOURCES) {
    await prisma.taintSource.upsert({
      where: { id: `src-${src.language}-${src.pattern}`.replace(/[^a-zA-Z0-9-_]/g, "_").slice(0, 25) },
      update: { pattern: src.pattern, category: src.category, isActive: true },
      create: { language: src.language, pattern: src.pattern, category: src.category },
    }).catch(async () => {
      // If upsert fails due to no unique constraint on pattern, use createMany skipDuplicates approach
      const existing = await prisma.taintSource.findFirst({ where: { language: src.language, pattern: src.pattern } });
      if (!existing) {
        await prisma.taintSource.create({ data: { language: src.language, pattern: src.pattern, category: src.category } });
      }
    });
  }

  // 2. Taint Sanitizers
  console.log(`[SEED-SECURITY] Seeding ${TAINT_SANITIZERS.length} taint sanitizers...`);
  for (const san of TAINT_SANITIZERS) {
    const existing = await prisma.taintSanitizer.findFirst({ where: { language: san.language, pattern: san.pattern } });
    if (!existing) {
      await prisma.taintSanitizer.create({ data: { language: san.language, pattern: san.pattern, category: san.category } });
    }
  }

  // 3. Taint Sinks
  console.log(`[SEED-SECURITY] Seeding ${TAINT_SINKS.length} taint sinks...`);
  for (const sink of TAINT_SINKS) {
    const existing = await prisma.taintSink.findFirst({ where: { language: sink.language, pattern: sink.pattern } });
    if (!existing) {
      await prisma.taintSink.create({ data: { language: sink.language, pattern: sink.pattern, cwe: sink.cwe, category: sink.category, severity: sink.severity, owasp2021: sink.owasp2021 } });
    }
  }

  // 4. Secret Patterns
  console.log(`[SEED-SECURITY] Seeding ${SECRET_PATTERNS.length} secret patterns...`);
  for (const sp of SECRET_PATTERNS) {
    await prisma.secretPattern.upsert({
      where: { ruleId: sp.ruleId },
      update: { name: sp.name, regex: sp.regex, severity: sp.severity, cwe: sp.cwe, description: sp.description, isActive: true },
      create: { ruleId: sp.ruleId, name: sp.name, regex: sp.regex, severity: sp.severity, cwe: sp.cwe, description: sp.description },
    });
  }

  // 5. IaC Rules
  console.log(`[SEED-SECURITY] Seeding ${IAC_RULES.length} IaC rules...`);
  for (const rule of IAC_RULES) {
    await prisma.iacRule.upsert({
      where: { ruleId: rule.ruleId },
      update: { name: rule.name, pattern: rule.pattern, severity: rule.severity, cwe: rule.cwe, category: rule.category, description: rule.description, fileTypes: rule.fileTypes, framework: rule.framework, isActive: true },
      create: { ruleId: rule.ruleId, name: rule.name, pattern: rule.pattern, severity: rule.severity, cwe: rule.cwe, category: rule.category, description: rule.description, fileTypes: rule.fileTypes, framework: rule.framework },
    });
  }

  // 6. Compliance Mappings
  console.log(`[SEED-SECURITY] Seeding ${COMPLIANCE_MAPPINGS.length} compliance mappings...`);
  for (const cm of COMPLIANCE_MAPPINGS) {
    await prisma.complianceMapping.upsert({
      where: { cwe: cm.cwe },
      update: { pciDss: cm.pciDss, hipaa: cm.hipaa, nist80053: cm.nist80053, iso27001: cm.iso27001, owasp2021: cm.owasp2021, owasp2017: cm.owasp2017, mitreTop25: cm.mitreTop25 },
      create: { cwe: cm.cwe, pciDss: cm.pciDss, hipaa: cm.hipaa, nist80053: cm.nist80053, iso27001: cm.iso27001, owasp2021: cm.owasp2021, owasp2017: cm.owasp2017, mitreTop25: cm.mitreTop25 },
    });
  }

  console.log("[SEED-SECURITY] ✅ Security rules seed complete!");
  console.log(`  - Taint Sources: ${TAINT_SOURCES.length}`);
  console.log(`  - Taint Sanitizers: ${TAINT_SANITIZERS.length}`);
  console.log(`  - Taint Sinks: ${TAINT_SINKS.length}`);
  console.log(`  - Secret Patterns: ${SECRET_PATTERNS.length}`);
  console.log(`  - IaC Rules: ${IAC_RULES.length}`);
  console.log(`  - Compliance Mappings: ${COMPLIANCE_MAPPINGS.length}`);
  console.log(`  TOTAL: ${TAINT_SOURCES.length + TAINT_SANITIZERS.length + TAINT_SINKS.length + SECRET_PATTERNS.length + IAC_RULES.length + COMPLIANCE_MAPPINGS.length} rules in DB`);
}

main()
  .catch((e) => {
    console.error("[SEED-SECURITY] Error:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
