"""Patterns for inventory.py: how to detect each stack, and the entry points and sinks to list for it.

Each stack has:
- detect: (manifest file glob, substrings) pairs; the stack matches when a file with that name contains any of
  the substrings (an empty tuple matches any such file).
- extensions: the source files the entry and sink patterns run on.
- entry: (kind, regex, path regex or None). A named group 'label' names the entry point (route, topic, class).
- entry_files: (kind, path regex); a matching file is itself an entry point (Next.js API routes, pages).
- entry_if (optional): (kind, regex, text regex); like entry, but only in files whose whole text matches the text
  regex (exported functions of a Next.js 'use server' module).
- sinks: (kind, area, regex). 'area' is the rules/ category file that reviews the sink.

Keep the stack names equal to the rules/stacks/ file stems. Patterns favour recall: a false hit costs a short
review, a missed sink can hide a finding.
"""

JAVA_SPRING = {
    "detect": [("pom.xml", ("springframework",)), ("build.gradle", ("springframework",)),
               ("build.gradle.kts", ("springframework",))],
    "extensions": (".java", ".kt"),
    "entry": [
        ("route", r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b(?:\((?P<label>[^)]*)\))?", None),
        ("consumer", r"@(?:KafkaListener|RabbitListener|JmsListener|SqsListener|StreamListener)\b"
                     r"(?:\((?P<label>[^)]*)\))?", None),
        ("websocket", r"@(?:MessageMapping|SubscribeMapping)\b(?:\((?P<label>[^)]*)\))?", None),
        ("job", r"@Scheduled\b(?:\((?P<label>[^)]*)\))?", None),
    ],
    "entry_files": [],
    "sinks": [
        ("sql", "injection-input",
         r"\b(?:createNativeQuery|createQuery|createSQLQuery)\s*\(|\bjdbcTemplate\.(?:query\w*|update|execute|"
         r"batchUpdate)\s*\(|\.(?:executeQuery|executeUpdate)\s*\("),
        ("command", "injection-input", r"Runtime\.getRuntime\(\)\.exec|\bnew ProcessBuilder\b"),
        ("deserialization", "injection-input",
         r"\bnew ObjectInputStream\b|\bXMLDecoder\b|\b(?:enable|activate)DefaultTyping\b|JsonTypeInfo\.Id\.CLASS"),
        ("xml-parser", "injection-input",
         r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SAXReader|SAXBuilder)\b"),
        ("expression", "injection-input", r"\bSpelExpressionParser\b|\bparseExpression\s*\("),
        ("file", "injection-input",
         r"\bnew File\s*\(|\bPaths\.get\s*\(|\bFiles\.(?:newInputStream|newOutputStream|readAllBytes|write|copy|"
         r"delete)\s*\(|\bMultipartFile\b"),
        ("outbound-http", "access-control",
         r"\bRestTemplate\b|\bWebClient\b|\bHttpURLConnection\b|\bnew URL\s*\(|\bOkHttpClient\b|@FeignClient\b"),
        ("redirect", "access-control", r"\"redirect:|\bsendRedirect\s*\(|\bRedirectView\b"),
        ("weak-crypto", "cryptography-data-protection",
         r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"|Cipher\.getInstance\(\s*\"[^\"]*(?:ECB|DES|RC4)|"
         r"\bnew Random\s*\("),
        ("tls", "cryptography-data-protection",
         r"\bX509TrustManager\b|\bNoopHostnameVerifier\b|\bsetHostnameVerifier\s*\(|ALLOW_ALL_HOSTNAME_VERIFIER"),
        ("token", "authentication-session", r"\bJwts\.parser|\bJWT\.(?:decode|require)\s*\(|\bJwtDecoder\b"),
    ],
}

NODE_BACKEND = {
    "detect": [("package.json", ('"express"', '"@nestjs/core"', '"fastify"', '"koa"', '"@hapi/hapi"', '"hono"',
                                 '"next"', '"nuxt"', '"@remix-run/', '"@sveltejs/kit"', '"astro"'))],
    "extensions": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"),
    "entry": [
        ("route", r"\b(?:app|router|server|api|fastify|routes)\.(?:get|post|put|patch|delete|all|options|route)"
                  r"\s*\(\s*(?P<label>['\"`][^'\"`]*['\"`])", None),
        ("route", r"@(?:Get|Post|Put|Patch|Delete|All|Options)\s*\((?P<label>[^)]*)\)", None),
        ("consumer", r"@(?:MessagePattern|EventPattern|Process|OnEvent|SubscribeMessage)\s*\((?P<label>[^)]*)\)",
         None),
        ("job", r"@(?:Cron|Interval|Timeout)\s*\((?P<label>[^)]*)\)", None),
        ("route", r"^\s*export\s+(?:async\s+)?(?:function|const)\s+(?P<label>GET|POST|PUT|PATCH|DELETE)\b", None),
        ("server-action", r"^\s+['\"]use server['\"]", None),
    ],
    "entry_if": [
        ("server-action", r"^\s*export\s+(?:default\s+)?(?:async\s+function\s*\*?\s*|const\s+)(?P<label>\w+)",
         r"\A(?:\s|//[^\n]*|/\*[\s\S]*?\*/)*['\"]use server['\"]"),
    ],
    "entry_files": [("route-file", r"(?:^|/)pages/api/"),
                    ("middleware", r"(?:^|/)(?:middleware|proxy)\.(?:js|mjs|ts)$")],
    "sinks": [
        ("command", "injection-input",
         r"(?<![\w.])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|\bchild_process\b"),
        ("code", "injection-input", r"(?<![\w.])eval\s*\(|\bnew Function\s*\(|\bvm\.(?:run\w*|Script)\b"),
        ("sql", "injection-input",
         r"\$(?:queryRawUnsafe|executeRawUnsafe)\b|\.raw\s*\(|\bsequelize\.query\s*\(|\.query\s*\(\s*`[^`]*\$\{|"
         r"\.query\s*\(\s*['\"][^'\"]*['\"]\s*\+"),
        ("nosql", "injection-input", r"\$where\b|\.find(?:One)?\s*\(\s*req\.(?:body|query|params)"),
        ("file", "injection-input",
         r"\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|rm)\b|"
         r"\bres\.(?:sendFile|download)\s*\(|\bmulter\b"),
        ("deserialization", "injection-input", r"\bunserialize\s*\(|node-serialize|\byaml\.load\s*\("),
        ("outbound-http", "access-control",
         r"\baxios(?:\.\w+)?\s*\(|\bgot(?:\.\w+)?\s*\(|\bhttps?\.(?:get|request)\s*\(|"
         r"(?<![\w.])fetch\s*\(\s*[^'\"`\s)]"),
        ("redirect", "access-control", r"\b(?:res|reply)\.redirect\s*\("),
        ("weak-crypto", "cryptography-data-protection",
         r"createHash\(\s*['\"](?:md5|sha1)['\"]|createCipher(?:iv)?\(\s*['\"][^'\"]*(?:ecb|des|rc4)|"
         r"\bMath\.random\s*\("),
        ("tls", "cryptography-data-protection", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"),
        ("token", "authentication-session", r"\bjwt\.(?:verify|decode|sign)\s*\(|\bjwtVerify\s*\("),
        ("cors", "configuration-supply-chain", r"(?<![\w.])cors\s*\(|Access-Control-Allow-Origin|\benableCors\s*\("),
    ],
}

PYTHON = {
    "detect": [(name, ("django", "fastapi", "flask", "starlette", "aiohttp", "litestar"))
               for name in ("pyproject.toml", "requirements*.txt", "Pipfile", "setup.py", "setup.cfg")],
    "extensions": (".py",),
    "entry": [
        ("route", r"@\w+\.(?:get|post|put|patch|delete|route|api_route|websocket)\s*\((?P<label>[^)]*)\)", None),
        ("route", r"\b(?:re_)?path\s*\(\s*(?P<label>r?['\"][^'\"]*['\"])", r"(?:^|/)urls\.py$"),
        ("view", r"^\s*class\s+(?P<label>\w+)\s*\([^)]*(?:ViewSet|APIView|View|Resource)\b", None),
        ("consumer", r"^\s*class\s+(?P<label>\w+)\s*\([^)]*WebsocketConsumer\b", None),
        ("job", r"@(?:shared_task|\w+\.task)\b", None),
    ],
    "entry_files": [],
    "sinks": [
        ("command", "injection-input", r"\bsubprocess\.\w+\s*\(|\bos\.(?:system|popen|exec\w*)\s*\("),
        ("code", "injection-input", r"(?<![\w.])(?:eval|exec)\s*\("),
        ("deserialization", "injection-input",
         r"\b(?:pickle|cPickle|dill|marshal|shelve)\.loads?\s*\(|\byaml\.(?:unsafe_)?load\s*\(|"
         r"\bjsonpickle\.decode\b"),
        ("sql", "injection-input",
         r"\.execute\s*\(\s*f['\"]|\.execute\s*\([^)]*%\s*\(|\.execute\s*\([^)]*\.format\(|\.raw\s*\(|"
         r"\bRawSQL\s*\(|\.extra\s*\(|\btext\s*\(\s*f['\"]"),
        ("template", "injection-input",
         r"\brender_template_string\s*\(|\bmark_safe\s*\(|\bMarkup\s*\(|autoescape\s*=\s*False"),
        ("xml-parser", "injection-input", r"\b(?:etree|ElementTree|minidom|sax|lxml)\.\w*(?:parse|fromstring)\b"),
        ("file", "injection-input",
         r"\bsend_file\s*\(|\bsend_from_directory\s*\(|\bFileResponse\s*\(|\bopen\s*\([^)]*request\.|"
         r"\bos\.path\.join\s*\([^)]*request\."),
        ("outbound-http", "access-control",
         r"\brequests\.(?:get|post|put|patch|delete|head|request)\s*\(|\bhttpx\.(?:get|post|put|patch|delete|"
         r"request|AsyncClient|Client)\b|\burlopen\s*\(|\baiohttp\.ClientSession\b"),
        ("redirect", "access-control", r"(?<![\w.])redirect\s*\(|\bHttpResponseRedirect\s*\(|\bRedirectResponse\s*\("),
        ("weak-crypto", "cryptography-data-protection",
         r"\bhashlib\.(?:md5|sha1)\s*\(|\bMODE_ECB\b|(?<![\w.])random\.(?:random|randint|choice|randrange)\s*\("),
        ("tls", "cryptography-data-protection", r"verify\s*=\s*False|\bCERT_NONE\b|_create_unverified_context"),
        ("token", "authentication-session", r"\bjwt\.(?:decode|encode)\s*\("),
        ("config", "configuration-supply-chain",
         r"^\s*DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*|CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True"),
    ],
}

GO = {
    "detect": [("go.mod", ())],
    "extensions": (".go",),
    "entry": [
        ("route", r"\.(?:GET|POST|PUT|PATCH|DELETE|Any|Handle|HandleFunc|Get|Post|Put|Patch|Delete|Group|Route)"
                  r"\s*\(\s*(?P<label>\"[^\"]*\")", None),
        ("grpc", r"\bRegister(?P<label>\w+)Server\s*\(", None),
        ("consumer", r"\.(?:Subscribe|QueueSubscribe|Consume)\s*\((?P<label>[^,)]*)", None),
    ],
    "entry_files": [],
    "sinks": [
        ("command", "injection-input", r"\bexec\.Command(?:Context)?\s*\("),
        ("sql", "injection-input",
         r"fmt\.Sprintf\(\s*\"\s*(?i:select|insert|update|delete|with)\b|"
         r"\.(?:Query|QueryRow|Exec|QueryContext|ExecContext|QueryRowContext|Raw|Where)\s*\([^)]*\+\s*\w"),
        ("template", "injection-input", r"\btemplate\.(?:HTML|JS|URL)\s*\(|\"text/template\""),
        ("file", "injection-input",
         r"\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll)\s*\(|\bhttp\.ServeFile\s*\(|"
         r"\bfilepath\.Join\s*\("),
        ("deserialization", "injection-input", r"\bgob\.NewDecoder\b|\bxml\.(?:Unmarshal|NewDecoder)\b"),
        ("outbound-http", "access-control",
         r"\bhttp\.(?:Get|Post|PostForm|Head|NewRequest(?:WithContext)?)\s*\(|\bclient\.Do\s*\("),
        ("redirect", "access-control", r"\bhttp\.Redirect\s*\(|\.Redirect\s*\(\s*(?:http\.Status|30\d)"),
        ("weak-crypto", "cryptography-data-protection",
         r"\b(?:md5|sha1)\.(?:New|Sum)\b|\bdes\.NewCipher\b|\brc4\.|\"math/rand\""),
        ("tls", "cryptography-data-protection", r"InsecureSkipVerify\s*:\s*true"),
        ("token", "authentication-session", r"\bjwt\.(?:Parse|ParseWithClaims|ParseUnverified)\s*\("),
    ],
}

DOTNET = {
    "detect": [("*.csproj", ("Microsoft.AspNetCore", "Microsoft.NET.Sdk.Web"))],
    "extensions": (".cs", ".cshtml", ".razor"),
    "entry": [
        ("route", r"\[(?:Http(?:Get|Post|Put|Patch|Delete)|Route)\b(?:\s*\((?P<label>[^)]*)\))?", None),
        ("route", r"\.Map(?:Get|Post|Put|Patch|Delete|Methods|Group|Hub|Grpc\w*)\s*(?:<[^>]*>)?\s*\(\s*"
                  r"(?P<label>\"[^\"]*\")?", None),
        ("hub", r"class\s+(?P<label>\w+)\s*:\s*Hub\b", None),
        ("job", r"class\s+(?P<label>\w+)\s*:\s*(?:BackgroundService|IHostedService)\b", None),
        ("page", r"^\s*@page\b\s*(?P<label>\"[^\"]*\")?", None),
    ],
    "entry_files": [],
    "sinks": [
        ("sql", "injection-input",
         r"\b(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQueryRaw)\s*\(|\bnew SqlCommand\s*\(|"
         r"\.CommandText\s*="),
        ("command", "injection-input", r"\bProcess\.Start\s*\(|\bProcessStartInfo\b"),
        ("deserialization", "injection-input",
         r"\b(?:BinaryFormatter|LosFormatter|NetDataContractSerializer|SoapFormatter)\b|"
         r"TypeNameHandling\.(?:All|Auto|Objects|Arrays)"),
        ("xml-parser", "injection-input", r"\bXmlDocument\b|\bXmlTextReader\b|DtdProcessing\.Parse"),
        ("file", "injection-input",
         r"\bFile\.(?:ReadAll\w*|WriteAll\w*|Open\w*|Delete|Copy|Move)\s*\(|\bPath\.Combine\s*\(|\bIFormFile\b|"
         r"\bPhysicalFile\s*\("),
        ("raw-html", "client-side", r"\bHtml\.Raw\s*\(|\bMarkupString\b"),
        ("outbound-http", "access-control",
         r"\bnew HttpClient\s*\(|\bIHttpClientFactory\b|\bWebRequest\.Create\s*\(|"
         r"\.(?:GetAsync|PostAsync|SendAsync|GetStringAsync)\s*\("),
        ("redirect", "access-control", r"\b(?:Redirect|RedirectPermanent|LocalRedirect)\s*\("),
        ("weak-crypto", "cryptography-data-protection",
         r"\b(?:MD5|SHA1)\.Create\s*\(|\b(?:MD5|DES)CryptoServiceProvider\b|CipherMode\.ECB|\bnew Random\s*\("),
        ("tls", "cryptography-data-protection",
         r"ServerCertificate(?:Custom)?ValidationCallback|DangerousAcceptAnyServerCertificateValidator"),
        ("token", "authentication-session",
         r"Validate(?:Issuer|Audience|Lifetime)\s*=\s*false|RequireSignedTokens\s*=\s*false|\bReadJwtToken\s*\("),
    ],
}

WEB_FRONTEND = {
    "detect": [("package.json", ('"react"', '"@angular/core"', '"vue"', '"svelte"', '"solid-js"', '"next"',
                                 '"nuxt"', '"astro"'))],
    "extensions": (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".astro"),
    "entry": [
        ("route", r"\bpath\s*:\s*(?P<label>['\"`][^'\"`]*['\"`])", r"(?i)rout"),
        ("route", r"<Route\b[^>]*\bpath\s*=\s*\{?(?P<label>['\"`][^'\"`]*['\"`])", None),
        ("message-listener", r"addEventListener\s*\(\s*['\"]message['\"]|\bonmessage\s*=", None),
        ("url-input", r"\blocation\.(?:hash|search)\b|\bnew URLSearchParams\s*\(|\buseSearchParams\s*\(|"
                      r"\$route\.query|\bActivatedRoute\b", None),
    ],
    "entry_files": [("page-file", r"(?:^|/)(?:pages|app|routes)/.*\.(?:jsx|tsx|vue|svelte|astro)$")],
    "sinks": [
        ("dom-html", "client-side",
         r"\bdangerouslySetInnerHTML\b|\.(?:innerHTML|outerHTML)\s*\+?=|\binsertAdjacentHTML\s*\(|"
         r"\bdocument\.write(?:ln)?\s*\(|\bv-html\b|\{@html\b|\bbypassSecurityTrust\w+\s*\(|\[innerHTML\]"),
        ("code", "client-side",
         r"(?<![\w.])eval\s*\(|\bnew Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*['\"`]"),
        ("navigation", "client-side",
         r"\blocation(?:\.href)?\s*=(?!=)|\blocation\.(?:assign|replace)\s*\(|\bwindow\.open\s*\("),
        ("post-message", "client-side", r"\.postMessage\s*\("),
        ("token-storage", "client-side", r"\b(?:localStorage|sessionStorage)\.setItem\s*\("),
        ("public-secret", "client-side",
         r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC|EXPO_PUBLIC)_(?!\w*(?:ANON|PUBLISHABLE)_KEY\b)"
         r"\w*(?:SECRET|KEY|TOKEN|PASSWORD)\b"),
    ],
}

MOBILE = {
    "detect": [("package.json", ('"react-native"', '"expo"')), ("pubspec.yaml", ()),
               ("AndroidManifest.xml", ()), ("Podfile", ())],
    "extensions": (".kt", ".java", ".swift", ".m", ".dart", ".js", ".jsx", ".ts", ".tsx", ".xml", ".plist"),
    "entry": [
        ("exported-component", r"android:exported\s*=\s*\"true\"", None),
        ("deep-link", r"<data\s[^>]*android:scheme\s*=\s*(?P<label>\"[^\"]*\")", None),
        ("deep-link", r"<key>CFBundleURLSchemes</key>|applinks:(?P<label>[\w.-]+)", None),
        ("deep-link", r"\bLinking\.(?:addEventListener|getInitialURL)\b|\buseURL\s*\(|\bonOpenURL\b|"
                      r"\bgetInitialLink\s*\(|\buriLinkStream\b|\bonNewIntent\s*\(", None),
        ("screen", r"<\w+\.Screen\b[^>]*\bname\s*=\s*(?P<label>['\"][^'\"]*['\"])", None),
    ],
    "entry_files": [],
    "sinks": [
        ("webview", "client-side",
         r"\baddJavascriptInterface\s*\(|\bsetJavaScriptEnabled\s*\(\s*true|\bsetAllowFileAccess\w*\s*\(\s*true|"
         r"\bWKWebView\b|\bevaluateJavascript\s*\(|\binjectedJavaScript\b|<WebView\b|\bWebViewController\b"),
        ("storage", "client-side",
         r"\bSharedPreferences\b|\bAsyncStorage\.setItem\s*\(|\b(?:NS)?UserDefaults\b|\bMMKV\b"),
        ("intent", "client-side",
         r"\bget\w*Extra\s*\(|\bPendingIntent\.get\w*\s*\(|\bsendBroadcast\s*\("),
        ("network", "cryptography-data-protection",
         r"NSAllowsArbitraryLoads|usesCleartextTraffic\s*=\s*\"true\"|cleartextTrafficPermitted\s*=\s*\"true\"|"
         r"\bonReceivedSslError\b|\bX509TrustManager\b|\bbadCertificateCallback\b"),
        ("logging", "logging-error-handling", r"\bLog\.[dvi]\s*\(|\bNSLog\s*\(|\bdebugPrint\s*\("),
    ],
}

BAAS = {
    "detect": [("package.json", ('"@supabase/supabase-js"', '"@supabase/ssr"', '"firebase"', '"firebase-admin"',
                                 '"firebase-functions"')),
               ("config.toml", ("supabase",)),
               ("*.sql", ("auth.uid()", "auth.jwt()", "row level security", "ROW LEVEL SECURITY")),
               ("firebase.json", ()), ("firestore.rules", ()), ("storage.rules", ()), ("database.rules.json", ()),
               ("pubspec.yaml", ("supabase_flutter", "cloud_firestore", "firebase_"))],
    "extensions": (".sql", ".rules", ".json", ".toml", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".dart"),
    "entry": [
        ("table", r"(?i)^\s*create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<label>[\w.\"]+)", r"\.sql$"),
        ("view", r"(?i)^\s*create\s+(?:or\s+replace\s+)?(?:materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?"
                 r"(?P<label>[\w.\"]+)", r"\.sql$"),
        ("rpc", r"(?i)^\s*create\s+(?:or\s+replace\s+)?function\s+(?P<label>[\w.\"]+)", r"\.sql$"),
        ("storage-bucket", r"(?i)\binsert\s+into\s+storage\.buckets\b", r"\.sql$"),
        ("rules-match", r"^\s*match\s+(?P<label>/[^\s{]+)", r"\.rules$"),
        ("cloud-function", r"^\s*(?:export\s+const\s+|exports\.)(?P<label>\w+)\s*=\s*(?:functions\.|"
                           r"on(?:Call|Request|Document\w+|Object\w+|Schedule|Value\w+|Message\w+|TaskDispatched)\b|"
                           r"before\w+\s*\()", None),
    ],
    "entry_files": [("edge-function", r"(?:^|/)supabase/functions/[^/_][^/]*/index\.(?:ts|js)$")],
    "sinks": [
        ("rls-disabled", "access-control", r"(?i)\bdisable\s+row\s+level\s+security\b|\bbypassrls\b"),
        ("policy", "access-control", r"(?i)^\s*(?:create|alter)\s+policy\b"),
        ("security-definer", "access-control", r"(?i)\bsecurity\s+definer\b"),
        ("grant", "access-control", r"(?i)\bgrant\b.*\bto\s+(?:anon|authenticated|public)\b"),
        ("user-metadata", "access-control", r"\buser_metadata\b|\braw_user_meta_data\b"),
        ("service-key", "access-control",
         r"(?i)\bservice_role\b|SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY|\bsb_secret_|\bfirebase-admin\b|"
         r"\badmin\.initializeApp\s*\(|"
         r"\"private_key\"\s*:"),
        ("open-rule", "access-control",
         r"\bif\s+true\b|\bif\s+request\.auth\s*!=\s*null\s*;|request\.time\s*<\s*timestamp\.date|"
         r"\"\.(?:read|write)\"\s*:\s*(?:true|\"true\"|\"auth\s*!=\s*null\")"),
        ("storage-bucket", "access-control", r"\.(?:createBucket|updateBucket)\s*\("),
        ("unverified-session", "authentication-session", r"\.auth\.getSession\s*\(|\bverify_jwt\s*=\s*false\b"),
    ],
}

STACKS = {
    "java-spring": JAVA_SPRING,
    "node-backend": NODE_BACKEND,
    "python": PYTHON,
    "go": GO,
    "dotnet": DOTNET,
    "web-frontend": WEB_FRONTEND,
    "mobile": MOBILE,
    "baas": BAAS,
}

# Paths never scanned: dependencies, build output and generated code. Supabase migrations are kept: they hold the
# RLS policies that are the API's access control.
SKIP_PATH = (r"(?:^|/)(?:node_modules|vendor|dist|build|out|target|bin|obj|\.next|\.nuxt|\.svelte-kit|coverage|"
             r"Pods|\.gradle|\.git|venv|\.venv|site-packages|__pycache__)/|(?:^|/)(?<!supabase/)migrations/|"
             r"\.min\.js$|\.d\.ts$")

# Test code is reviewed only through the tests check in rules/00-overview.md, not as attack surface.
TEST_PATH = (r"(?:^|/)(?:tests?|__tests__|__mocks__|specs?|testdata|fixtures|mocks?|e2e|cypress)/|"
             r"(?:^|/)src/test/|[._-](?:test|spec)\.\w+$|_test\.go$|(?:^|/)test_[^/]*\.py$|Tests?\.(?:cs|java|kt)$")

# Lines skipped before matching: imports name an API without using it. Narrow enough that SQL lines starting with
# "using (" or "from" and C# using declarations ("using var x = ...") still count as code.
IMPORT_LINE = (r"^\s*(?:import\s|package\s|#include\b|@import\b|from\s+\S+\s+import\b|"
               r"(?:global\s+)?using\s+(?:static\s+)?[\w.]+\s*(?:=\s*[\w.<>]+\s*)?;)")
