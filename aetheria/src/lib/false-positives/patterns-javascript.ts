/**
 * False Positive Patterns for JavaScript/TypeScript
 * Common development patterns that are not actual vulnerabilities
 */

export const JAVASCRIPT_FALSE_POSITIVES = [
  {
    language: "javascript",
    pattern: "console\\.(log|debug|info|warn|error)\\(",
    description: "Console logging in development",
    reason: "Console statements are commonly used for debugging and are typically removed in production builds or handled by build tools",
    context: "development",
    cweIds: ["CWE-532"], // Information Exposure Through Log Files
    examples: [
      'console.log("Debug info:", data);',
      'console.error("Error occurred:", error);',
      'console.warn("Deprecated API used");',
    ],
  },
  {
    language: "javascript",
    pattern: "debugger;",
    description: "Debugger statement",
    reason: "Debugger statements are development tools and are removed by minifiers/build tools in production",
    context: "development",
    cweIds: ["CWE-489"], // Active Debug Code
    examples: [
      'debugger; // Intentional breakpoint',
      'if (process.env.NODE_ENV === "development") { debugger; }',
    ],
  },
  {
    language: "javascript",
    pattern: "\\$\\{.*\\}.*innerHTML",
    description: "Template literal with innerHTML when sanitized",
    reason: "When using DOMPurify or similar sanitization libraries, innerHTML with template literals is safe",
    context: "sanitized",
    cweIds: ["CWE-79"], // XSS
    examples: [
      'element.innerHTML = DOMPurify.sanitize(`<div>${userInput}</div>`);',
      'const clean = sanitizeHtml(template); element.innerHTML = clean;',
    ],
  },
  {
    language: "javascript",
    pattern: "eval\\(.*JSON\\.stringify",
    description: "eval() with JSON.stringify",
    reason: "Using eval with JSON.stringify is redundant but not a security issue since JSON.stringify escapes dangerous characters",
    context: "json",
    cweIds: ["CWE-94"], // Code Injection
    examples: [
      'eval("var data = " + JSON.stringify(safeData));',
    ],
  },
  {
    language: "javascript",
    pattern: "new Function\\(.*\\)",
    description: "Function constructor in controlled environment",
    reason: "When used with trusted, developer-controlled code (not user input), Function constructor is safe",
    context: "trusted",
    cweIds: ["CWE-94"], // Code Injection
    examples: [
      'const fn = new Function("a", "b", "return a + b"); // Math operation',
      'const template = new Function("data", "return `Hello ${data.name}`");',
    ],
  },
  {
    language: "javascript",
    pattern: "__dirname|__filename",
    description: "Node.js path constants",
    reason: "These are built-in Node.js constants that provide the current directory/file path, not user input",
    context: "nodejs",
    cweIds: ["CWE-22"], // Path Traversal
    examples: [
      'const configPath = path.join(__dirname, "config.json");',
      'const filePath = path.resolve(__filename, "../data");',
    ],
  },
  {
    language: "javascript",
    pattern: "process\\.env\\.",
    description: "Environment variables",
    reason: "Environment variables are set by administrators, not user input. They are a standard configuration method",
    context: "configuration",
    cweIds: ["CWE-526"], // Information Exposure Through Environment Variables
    examples: [
      'const apiKey = process.env.API_KEY;',
      'const dbUrl = process.env.DATABASE_URL;',
    ],
  },
  {
    language: "javascript",
    pattern: "localStorage\\.(setItem|getItem)",
    description: "localStorage usage",
    reason: "localStorage is client-side only and appropriate for non-sensitive data like UI preferences",
    context: "non-sensitive",
    cweIds: ["CWE-922"], // Insecure Storage
    examples: [
      'localStorage.setItem("theme", "dark");',
      'const lang = localStorage.getItem("preferredLanguage");',
    ],
  },
  {
    language: "javascript",
    pattern: "setTimeout\\(.*\\,\\s*0\\)",
    description: "setTimeout with 0 delay",
    reason: "setTimeout(..., 0) is a common pattern to defer execution to the next event loop tick, not a timing attack",
    context: "event-loop",
    cweIds: ["CWE-362"], // Race Condition
    examples: [
      'setTimeout(() => updateUI(), 0); // Defer to next tick',
      'setTimeout(callback, 0); // Async execution',
    ],
  },
  {
    language: "typescript",
    pattern: "as\\s+any",
    description: "TypeScript 'as any' type assertion",
    reason: "While not ideal, 'as any' is sometimes necessary for complex types or third-party libraries without types",
    context: "type-system",
    cweIds: ["CWE-704"], // Incorrect Type Conversion
    examples: [
      'const data = JSON.parse(jsonString) as any;',
      'const element = document.querySelector(".item") as any;',
    ],
  },
  {
    language: "javascript",
    pattern: "\\!\\!",
    description: "Double negation for boolean conversion",
    reason: "!! is a safe idiom for converting values to boolean, commonly used in JavaScript",
    context: "type-conversion",
    cweIds: ["CWE-704"], // Incorrect Type Conversion
    examples: [
      'const isValid = !!value;',
      'return !!user && !!user.isActive;',
    ],
  },
  {
    language: "javascript",
    pattern: "Array\\.prototype\\.(map|filter|reduce)",
    description: "Array prototype methods",
    reason: "Standard array methods are safe and part of the JavaScript specification",
    context: "standard-library",
    cweIds: ["CWE-1321"], // Prototype Pollution
    examples: [
      'const ids = users.map(u => u.id);',
      'const active = items.filter(i => i.isActive);',
    ],
  },
  {
    language: "javascript",
    pattern: "JSON\\.parse\\(.*process\\.env",
    description: "JSON.parse with environment variables",
    reason: "Parsing JSON from environment variables is a standard configuration pattern",
    context: "configuration",
    cweIds: ["CWE-502"], // Deserialization
    examples: [
      'const config = JSON.parse(process.env.APP_CONFIG || "{}");',
    ],
  },
  {
    language: "javascript",
    pattern: "require\\(['\"]\\.\\/",
    description: "Relative require() statements",
    reason: "Relative requires are standard Node.js module imports, not dynamic code loading",
    context: "module-system",
    cweIds: ["CWE-829"], // Inclusion of Functionality from Untrusted Control Sphere
    examples: [
      'const utils = require("./utils");',
      'const config = require("../config/database");',
    ],
  },
  {
    language: "javascript",
    pattern: "(bcrypt|bcryptjs|scrypt|argon2|pbkdf2)\\.(hash|compare|genSalt|hashSync|compareSync)",
    description: "Secure password hashing with bcrypt/scrypt/argon2",
    reason: "bcrypt, scrypt, and argon2 are industry-standard secure password hashing algorithms. CWE-327 does not apply to these.",
    context: "cryptography",
    cweIds: ["CWE-327", "CWE-328"], // Broken Crypto / Use of Weak Hash
    examples: [
      'const hash = await bcrypt.hash(password, 12);',
      'const valid = await bcrypt.compare(input, storedHash);',
      'const hash = bcrypt.hashSync(password, bcrypt.genSaltSync(10));',
    ],
  },
  {
    language: "typescript",
    pattern: "(bcrypt|bcryptjs|scrypt|argon2|pbkdf2)\\.(hash|compare|genSalt|hashSync|compareSync)",
    description: "Secure password hashing with bcrypt/scrypt/argon2",
    reason: "bcrypt, scrypt, and argon2 are industry-standard secure password hashing algorithms. CWE-327 does not apply to these.",
    context: "cryptography",
    cweIds: ["CWE-327", "CWE-328"],
    examples: [
      'const hash = await bcrypt.hash(password, 12);',
      'const valid = await bcrypt.compare(input, storedHash);',
    ],
  },
  {
    language: "javascript",
    pattern: "import.*from\\s+['\"](bcrypt|bcryptjs|argon2|scrypt)",
    description: "Import of secure password hashing library",
    reason: "Importing bcrypt/argon2/scrypt is a security best practice for password storage, not a vulnerability",
    context: "cryptography",
    cweIds: ["CWE-327", "CWE-328"],
    examples: [
      'import bcrypt from "bcryptjs";',
      'import { hash, compare } from "argon2";',
    ],
  },
  {
    language: "typescript",
    pattern: "import.*from\\s+['\"](bcrypt|bcryptjs|argon2|scrypt)",
    description: "Import of secure password hashing library",
    reason: "Importing bcrypt/argon2/scrypt is a security best practice for password storage, not a vulnerability",
    context: "cryptography",
    cweIds: ["CWE-327", "CWE-328"],
    examples: [
      'import bcrypt from "bcryptjs";',
      'import { hash, compare } from "argon2";',
    ],
  },

  // === Node.js: Express / NestJS Framework Patterns ===
  {
    language: "javascript",
    pattern: "helmet\\(|app\\.use\\(helmet|cors\\(|app\\.use\\(cors",
    description: "Express security middleware (helmet/cors)",
    reason: "Helmet sets security headers and CORS configures cross-origin policy — these ARE the security controls",
    context: "framework",
    cweIds: ["CWE-693", "CWE-1021", "CWE-942"],
    examples: [
      'app.use(helmet());',
      'app.use(cors({ origin: "https://app.example.com" }));',
    ],
  },
  {
    language: "javascript",
    pattern: "rateLimit|rate-limit|express-rate-limit|@nestjs/throttler",
    description: "Rate limiting middleware",
    reason: "Rate limiting IS the protection against brute-force and DoS, not a vulnerability",
    context: "framework",
    cweIds: ["CWE-770", "CWE-307"],
    examples: [
      'app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));',
      '@UseGuards(ThrottlerGuard)',
    ],
  },
  {
    language: "typescript",
    pattern: "@(Controller|Injectable|Module|Guard|Pipe|Interceptor|Middleware)\\(",
    description: "NestJS framework decorators",
    reason: "Standard NestJS dependency injection and routing decorators, not code injection",
    context: "framework",
    cweIds: ["CWE-94", "CWE-915"],
    examples: [
      '@Controller("users")',
      '@Injectable() export class UsersService {}',
      '@UseGuards(JwtAuthGuard)',
    ],
  },
  {
    language: "typescript",
    pattern: "@(Get|Post|Put|Patch|Delete|Options|Head)\\(",
    description: "NestJS HTTP method decorators",
    reason: "Standard NestJS route definition decorators",
    context: "framework",
    cweIds: ["CWE-862"],
    examples: [
      '@Get(":id")',
      '@Post() create(@Body() dto: CreateUserDto) {}',
    ],
  },

  // === Node.js: Authentication & JWT ===
  {
    language: "javascript",
    pattern: "jwt\\.(sign|verify)\\(|jsonwebtoken",
    description: "JWT sign/verify operations",
    reason: "JWT signing and verification with proper libraries is a standard secure authentication mechanism",
    context: "cryptography",
    cweIds: ["CWE-327", "CWE-347"],
    examples: [
      'const token = jwt.sign({ userId }, secret, { expiresIn: "1h" });',
      'const decoded = jwt.verify(token, process.env.JWT_SECRET);',
    ],
  },
  {
    language: "javascript",
    pattern: "passport\\.(authenticate|use|serializeUser|deserializeUser)",
    description: "Passport.js authentication framework",
    reason: "Passport.js is a mature, widely-used authentication middleware for Node.js",
    context: "framework",
    cweIds: ["CWE-287", "CWE-306"],
    examples: [
      'app.use(passport.authenticate("jwt", { session: false }));',
      'passport.use(new LocalStrategy(usernameField: "email"));',
    ],
  },
  {
    language: "javascript",
    pattern: "cookie-parser|cookieParser|express-session|cookieSession",
    description: "Cookie/session middleware",
    reason: "Standard Express session management with proper configuration is secure",
    context: "framework",
    cweIds: ["CWE-614", "CWE-1004"],
    examples: [
      'app.use(session({ secret, resave: false, saveUninitialized: false, cookie: { httpOnly: true, secure: true } }));',
    ],
  },

  // === Node.js: ORM & Database (Parameterized) ===
  {
    language: "javascript",
    pattern: "prisma\\.[a-z]+\\.(findMany|findFirst|findUnique|create|update|delete|upsert|groupBy)",
    description: "Prisma ORM operations",
    reason: "Prisma ORM generates parameterized queries internally, preventing SQL injection",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      'const users = await prisma.user.findMany({ where: { email } });',
      'await prisma.vulnerability.create({ data: { title, severity } });',
    ],
  },
  {
    language: "javascript",
    pattern: "mongoose\\.|Model\\.(find|findOne|create|updateOne|deleteOne|aggregate)",
    description: "Mongoose ODM operations",
    reason: "Mongoose sanitizes queries by default and uses MongoDB driver parameterization",
    context: "safe-sql",
    cweIds: ["CWE-89", "CWE-943"],
    examples: [
      'const user = await User.findOne({ email: req.body.email });',
      'await Product.create({ name, price, category });',
    ],
  },
  {
    language: "javascript",
    pattern: "knex\\(|\\.where\\(|\\.whereRaw\\(.*\\[",
    description: "Knex.js query builder with bindings",
    reason: "Knex query builder uses parameterized queries when using proper binding syntax",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      'await knex("users").where({ email }).first();',
      'await knex("orders").whereRaw("created_at > ?", [date]);',
    ],
  },

  // === Node.js: Crypto (Proper Usage) ===
  {
    language: "javascript",
    // NOTE: createHash is intentionally NOT matched here — its safety depends on the
    // algorithm (md5/sha1 are WEAK and must stay flagged). A createHash call with
    // a strong algorithm (sha256+) is dismissed by the high-precision "strong-hash"
    // rule in false-positive-detector.ts, which inspects the actual algorithm.
    pattern: "crypto\\.(createHmac|createCipheriv|createDecipheriv|randomBytes|randomUUID|pbkdf2|scrypt)",
    description: "Node.js crypto module proper usage",
    reason: "Node.js crypto module with HMAC, AES-256-GCM, randomBytes, pbkdf2 and scrypt is cryptographically secure",
    context: "cryptography",
    cweIds: ["CWE-327", "CWE-328", "CWE-330"],
    examples: [
      'const iv = crypto.randomBytes(16);',
      'const key = crypto.scryptSync(password, salt, 64);',
      'const mac = crypto.createHmac("sha256", key).update(data).digest("hex");',
    ],
  },
  {
    language: "javascript",
    pattern: "crypto\\.subtle|SubtleCrypto|webcrypto",
    description: "Web Crypto API usage",
    reason: "Web Crypto API provides secure cryptographic operations in browsers and Node.js",
    context: "cryptography",
    cweIds: ["CWE-327", "CWE-328"],
    examples: [
      'await crypto.subtle.digest("SHA-256", data);',
      'const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 });',
    ],
  },

  // === Node.js: Validation & Sanitization ===
  {
    language: "typescript",
    pattern: "z\\.(object|string|number|boolean|array|enum|union|optional|nullable)",
    description: "Zod schema validation",
    reason: "Zod provides runtime type validation that prevents injection and type confusion attacks",
    context: "validation",
    cweIds: ["CWE-20", "CWE-915"],
    examples: [
      'const schema = z.object({ email: z.string().email(), age: z.number().min(0) });',
      'const result = schema.safeParse(req.body);',
    ],
  },
  {
    language: "javascript",
    pattern: "class-validator|class-transformer|@IsString|@IsEmail|@IsNumber|@IsNotEmpty|@MaxLength|@MinLength",
    description: "NestJS class-validator decorators",
    reason: "class-validator provides declarative DTO validation that prevents malformed input attacks",
    context: "validation",
    cweIds: ["CWE-20", "CWE-915"],
    examples: [
      '@IsEmail() email: string;',
      '@IsString() @MaxLength(100) name: string;',
    ],
  },
  {
    language: "javascript",
    pattern: "DOMPurify|sanitize-html|xss|escape-html|he\\.encode",
    description: "HTML sanitization libraries",
    reason: "Using sanitization libraries IS the fix for XSS, not a vulnerability",
    context: "sanitized",
    cweIds: ["CWE-79"],
    examples: [
      'const clean = DOMPurify.sanitize(dirty);',
      'const safe = sanitizeHtml(userInput, { allowedTags: ["b", "i"] });',
    ],
  },

  // === Node.js: Next.js Patterns ===
  {
    language: "typescript",
    pattern: "getServerSideProps|getStaticProps|getStaticPaths",
    description: "Next.js data fetching functions",
    reason: "Server-side data fetching in Next.js runs on the server, not exposed to client",
    context: "framework",
    cweIds: ["CWE-200", "CWE-526"],
    examples: [
      'export async function getServerSideProps(context) { return { props: {} }; }',
      'export const getStaticProps = async () => ({ props: { data } });',
    ],
  },
  {
    language: "typescript",
    pattern: "NextResponse|NextRequest|NextApiRequest|NextApiResponse",
    description: "Next.js API route types",
    reason: "Standard Next.js request/response handling in API routes",
    context: "framework",
    cweIds: ["CWE-200"],
    examples: [
      'export async function GET(request: NextRequest) { return NextResponse.json(data); }',
      'export default function handler(req: NextApiRequest, res: NextApiResponse) {}',
    ],
  },

  // === Node.js: Logging (Production-grade) ===
  {
    language: "javascript",
    pattern: "winston|pino|bunyan|logger\\.(info|warn|error|debug|trace|fatal)",
    description: "Production logging frameworks",
    reason: "Winston/Pino/Bunyan are production-grade loggers with structured output and log rotation",
    context: "logging",
    cweIds: ["CWE-532"],
    examples: [
      'logger.info("User logged in", { userId: user.id });',
      'const log = pino({ level: "info" }); log.error(err);',
    ],
  },

  // === Node.js: Error Handling ===
  {
    language: "javascript",
    pattern: "app\\.use\\(\\s*\\(err|error.*middleware|catch\\s*\\(|\\.catch\\(",
    description: "Express error handling middleware",
    reason: "Error handling middleware prevents stack trace leakage and handles errors gracefully",
    context: "error-handling",
    cweIds: ["CWE-209", "CWE-755"],
    examples: [
      'app.use((err, req, res, next) => { res.status(500).json({ error: "Internal error" }); });',
      'router.get("/", asyncHandler(async (req, res) => {}));',
    ],
  },

  // === Node.js: File Upload (Controlled) ===
  {
    language: "javascript",
    pattern: "multer|busboy|formidable|express-fileupload",
    description: "File upload middleware",
    reason: "Standard file upload libraries with size limits and type filtering are secure when configured",
    context: "framework",
    cweIds: ["CWE-434"],
    examples: [
      'const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 }, fileFilter });',
      'app.post("/upload", upload.single("file"), handler);',
    ],
  },

  // === Node.js: Streams & Events ===
  {
    language: "javascript",
    pattern: "EventEmitter|\\.on\\(|\\.emit\\(|\\.once\\(",
    description: "Node.js EventEmitter pattern",
    reason: "EventEmitter is the core Node.js event system, not a code injection vector",
    context: "language-feature",
    cweIds: ["CWE-94", "CWE-915"],
    examples: [
      'const emitter = new EventEmitter(); emitter.on("data", handler);',
      'process.on("uncaughtException", (err) => { logger.error(err); });',
    ],
  },
  {
    language: "javascript",
    pattern: "createReadStream|createWriteStream|pipeline|stream\\.",
    description: "Node.js stream operations",
    reason: "Streams are the standard Node.js I/O pattern for efficient data processing",
    context: "language-feature",
    cweIds: ["CWE-400", "CWE-770"],
    examples: [
      'const rs = fs.createReadStream(filePath); rs.pipe(res);',
      'pipeline(readStream, transform, writeStream, callback);',
    ],
  },

  // === Node.js: Worker Threads & Cluster ===
  {
    language: "javascript",
    pattern: "worker_threads|Worker\\(|parentPort|workerData",
    description: "Node.js worker threads",
    reason: "Worker threads are the standard Node.js parallelism mechanism with message-passing isolation",
    context: "concurrency",
    cweIds: ["CWE-362", "CWE-567"],
    examples: [
      'const worker = new Worker("./processor.js", { workerData: { id } });',
      'parentPort.postMessage(result);',
    ],
  },

  // === TypeScript: Decorators & DI ===
  {
    language: "typescript",
    pattern: "reflect-metadata|Reflect\\.defineMetadata|@Inject|@Provide",
    description: "TypeScript dependency injection metadata",
    reason: "Standard DI container metadata for NestJS/InversifyJS/TypeDI",
    context: "framework",
    cweIds: ["CWE-915"],
    examples: [
      '@Inject("USER_REPO") private userRepo: UserRepository',
      'Reflect.defineMetadata("design:paramtypes", types, target);',
    ],
  },
  {
    language: "typescript",
    pattern: "interface\\s+\\w+|type\\s+\\w+\\s*=",
    description: "TypeScript type definitions",
    reason: "TypeScript interfaces and type aliases are compile-time only, erased at runtime",
    context: "type-system",
    cweIds: ["CWE-704"],
    examples: [
      'interface User { id: string; email: string; }',
      'type Result = Success | Failure;',
    ],
  },

  // === Node.js: HTTPS/TLS ===
  {
    language: "javascript",
    pattern: "https\\.createServer|tls\\.|createSecureContext|SSL_CERT|NODE_TLS",
    description: "HTTPS/TLS server configuration",
    reason: "TLS configuration IS the security control for transport encryption",
    context: "cryptography",
    cweIds: ["CWE-319", "CWE-326"],
    examples: [
      'https.createServer({ key, cert }, app).listen(443);',
      'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";',
    ],
  },

  // === Node.js: CSRF Protection ===
  {
    language: "javascript",
    pattern: "csurf|csrf|csrfToken|_csrf|x-csrf-token",
    description: "CSRF protection middleware",
    reason: "CSRF token generation and validation IS the security control",
    context: "framework",
    cweIds: ["CWE-352"],
    examples: [
      'app.use(csrf({ cookie: true }));',
      'res.cookie("XSRF-TOKEN", req.csrfToken());',
    ],
  },
];
