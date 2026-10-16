"""Unit tests for inventory.py and inventory_patterns.py. Run: python -I test_inventory.py"""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import inventory  # noqa: E402
import inventory_patterns as patterns  # noqa: E402

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")

# One line per stack that each listed entry or sink kind must match: guards against broken patterns. An optional
# fourth item is the file path, for patterns limited to some files.
SAMPLES = {
    "java-spring": [
        ('@GetMapping("/cards/{id}")', "entry", "route"),
        ('@KafkaListener(topics = "payments")', "entry", "consumer"),
        ('em.createNativeQuery("select * from t where id=" + id)', "sink", "sql"),
        ("new ProcessBuilder(cmd).start();", "sink", "command"),
        ("RestTemplate rest = new RestTemplate();", "sink", "outbound-http"),
        ('MessageDigest.getInstance("MD5")', "sink", "weak-crypto"),
    ],
    "node-backend": [
        ("router.post('/login', handler)", "entry", "route"),
        ("@Get(':id')", "entry", "route"),
        ("export async function POST(req) {", "entry", "route"),
        ("  'use server'", "entry", "server-action"),
        ("'use server'\nexport async function deleteCard(id) {", "entry", "server-action"),
        ("exec(`ls ${dir}`)", "sink", "command"),
        ("db.query(`select * from users where id = ${id}`)", "sink", "sql"),
        ("const r = await fetch(url)", "sink", "outbound-http"),
        ("res.redirect(req.query.next)", "sink", "redirect"),
        ("jwt.verify(token, key)", "sink", "token"),
    ],
    "python": [
        ('@app.get("/items/{item_id}")', "entry", "route"),
        ("class CardViewSet(viewsets.ModelViewSet):", "entry", "view"),
        ("subprocess.run(cmd, shell=True)", "sink", "command"),
        ('cursor.execute(f"select * from t where id={id}")', "sink", "sql"),
        ("pickle.loads(data)", "sink", "deserialization"),
        ("requests.get(url)", "sink", "outbound-http"),
        ("requests.get(url, verify=False)", "sink", "tls"),
    ],
    "go": [
        ('r.GET("/cards/:id", h.Get)', "entry", "route"),
        ("pb.RegisterCardsServer(s, srv)", "entry", "grpc"),
        ('exec.Command("sh", "-c", c)', "sink", "command"),
        ('q := fmt.Sprintf("SELECT * FROM t WHERE id=%s", id)', "sink", "sql"),
        ("InsecureSkipVerify: true,", "sink", "tls"),
    ],
    "dotnet": [
        ('[HttpGet("{id}")]', "entry", "route"),
        ('app.MapPost("/pay", Pay);', "entry", "route"),
        ("db.Users.FromSqlRaw(sql)", "sink", "sql"),
        ("var f = new BinaryFormatter();", "sink", "deserialization"),
        ("@Html.Raw(Model.Bio)", "sink", "raw-html"),
    ],
    "web-frontend": [
        ("<Route path=\"/admin\" element={<Admin/>} />", "entry", "route"),
        ("window.addEventListener('message', onMsg)", "entry", "message-listener"),
        ("<div dangerouslySetInnerHTML={{__html: x}} />", "sink", "dom-html"),
        ("localStorage.setItem('token', t)", "sink", "token-storage"),
        ("window.location.href = next", "sink", "navigation"),
    ],
    "mobile": [
        ('<activity android:name=".Main" android:exported="true">', "entry", "exported-component"),
        ('<data android:scheme="myapp" />', "entry", "deep-link"),
        ("webView.addJavascriptInterface(bridge, \"Android\")", "sink", "webview"),
        ("AsyncStorage.setItem('token', t)", "sink", "storage"),
        ("<key>NSAllowsArbitraryLoads</key>", "sink", "network"),
    ],
    "baas": [
        ("create table if not exists public.profiles (", "entry", "table", "a.sql"),
        ('CREATE OR REPLACE VIEW public."CardSummary" AS', "entry", "view", "a.sql"),
        ("create or replace function public.transfer(amount int)", "entry", "rpc", "a.sql"),
        ("insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);", "entry",
         "storage-bucket", "a.sql"),
        ("    match /users/{userId} {", "entry", "rules-match", "firestore.rules"),
        ("export const addCredits = onCall(async (request) => {", "entry", "cloud-function"),
        ("exports.api = functions.https.onRequest(app);", "entry", "cloud-function"),
        ("alter table public.cards disable row level security;", "sink", "rls-disabled"),
        ('create policy "own rows" on public.cards for select using (true);', "sink", "policy"),
        ("security definer set search_path = ''", "sink", "security-definer"),
        ("grant all on table public.cards to anon;", "sink", "grant"),
        ("using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin')", "sink", "user-metadata"),
        ("const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)", "sink", "service-key"),
        ("createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_KEY!)", "sink", "service-key"),
        ("      allow read, write: if true;", "sink", "open-rule"),
        ("      allow read: if request.auth != null;", "sink", "open-rule"),
        ('    ".write": true,', "sink", "open-rule"),
        ("await supabase.storage.createBucket('docs', { public: true })", "sink", "storage-bucket"),
        ("const { data: { session } } = await supabase.auth.getSession()", "sink", "unverified-session"),
        ("verify_jwt = false", "sink", "unverified-session"),
    ],
}


def write(root, path, text):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as handle:
        handle.write(text)


class TempRepo(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)


class PatternsTest(unittest.TestCase):
    def test_stack_names_match_stack_files(self):
        stems = {n[:-3] for n in os.listdir(os.path.join(RULES_DIR, "stacks")) if n.endswith(".md")}
        self.assertEqual(set(patterns.STACKS), stems)

    def test_regexes_compile(self):
        for spec in patterns.STACKS.values():
            for _, regex, path_regex in spec["entry"]:
                re.compile(regex)
                if path_regex:
                    re.compile(path_regex)
            for _, regex, text_regex in spec.get("entry_if", ()):
                re.compile(regex)
                re.compile(text_regex)
            for _, regex in spec["entry_files"]:
                re.compile(regex)
            for _, _, regex in spec["sinks"]:
                re.compile(regex)

    def test_sink_areas_are_category_files(self):
        stems = {n[:-3] for n in os.listdir(RULES_DIR) if n.endswith(".md") and n != "00-overview.md"}
        for spec in patterns.STACKS.values():
            for kind, area, _ in spec["sinks"]:
                self.assertIn(area, stems, kind)

    def test_samples_match(self):
        for stack, samples in SAMPLES.items():
            spec = patterns.STACKS[stack]
            for line, side, kind, path in ((sample + ("x",))[:4] for sample in samples):
                if side == "entry":
                    found = {h["kind"] for h in inventory.entry_hits(path, line, stack, spec)}
                else:
                    found = {h["kind"] for h in inventory.sink_hits(path, line, stack, spec)}
                self.assertIn(kind, found, "%s: %s" % (stack, line))


class RunGitTest(TempRepo):
    def test_not_a_repo_returns_none(self):
        self.assertIsNone(inventory.run_git(self.root, "rev-parse", "HEAD"))

    def test_git_files_none_outside_repo(self):
        self.assertIsNone(inventory.git_files(self.root))


class ExclusionTest(unittest.TestCase):
    def test_excluded(self):
        for path in ("node_modules/x/index.js", "src/test/java/A.java", "a/b.test.ts", "pkg/a_test.go",
                     "tests/test_api.py", "app.min.js", "types.d.ts", "src/CardTests.cs"):
            self.assertTrue(inventory.is_excluded(path), path)

    def test_kept(self):
        for path in ("src/main/java/CardController.java", "app/api/route.ts", "server/main.go"):
            self.assertFalse(inventory.is_excluded(path), path)

    def test_only_supabase_migrations_kept(self):
        self.assertFalse(inventory.is_excluded("supabase/migrations/001_init.sql"))
        self.assertFalse(inventory.is_excluded("apps/db/supabase/migrations/001_init.sql"))
        for path in ("migrations/0001_initial.py", "app/migrations/0001_initial.py", "prisma/migrations/1/m.sql"):
            self.assertTrue(inventory.is_excluded(path), path)

    def test_in_scope(self):
        self.assertTrue(inventory.in_scope("src/a.py", ()))
        self.assertTrue(inventory.in_scope("src/a.py", ["src/"]))
        self.assertFalse(inventory.in_scope("lib/a.py", ["src/"]))


class FilesTest(TempRepo):
    def test_walk_files_skips_dependencies(self):
        write(self.root, "src/app.js", "")
        write(self.root, "node_modules/x/i.js", "")
        self.assertEqual(inventory.walk_files(self.root), ["src/app.js"])

    def test_walk_files_skips_by_full_path(self):
        write(self.root, "supabase/migrations/001.sql", "")
        write(self.root, "app/migrations/0001.py", "")
        self.assertEqual(inventory.walk_files(self.root), ["supabase/migrations/001.sql"])

    def test_list_files_filters_tests_and_scope(self):
        write(self.root, "src/app.js", "")
        write(self.root, "src/app.test.js", "")
        write(self.root, "lib/util.js", "")
        self.assertEqual(inventory.list_files(self.root), ["lib/util.js", "src/app.js"])
        self.assertEqual(inventory.list_files(self.root, ["src/"]), ["src/app.js"])

    def test_read_text_size_limit(self):
        write(self.root, "big.js", "x" * 20)
        old = inventory.MAX_BYTES
        inventory.MAX_BYTES = 10
        self.addCleanup(setattr, inventory, "MAX_BYTES", old)
        self.assertIsNone(inventory.read_text(self.root, "big.js"))
        self.assertIsNone(inventory.read_text(self.root, "missing.js"))


class DetectTest(TempRepo):
    def test_manifest_matches(self):
        self.assertTrue(inventory.manifest_matches("anything", ()))
        self.assertTrue(inventory.manifest_matches('"express": "4"', ('"express"',)))
        self.assertFalse(inventory.manifest_matches("{}", ('"express"',)))
        self.assertFalse(inventory.manifest_matches(None, ()))

    def test_detect_stacks(self):
        write(self.root, "api/package.json", '{"dependencies": {"express": "4"}}')
        write(self.root, "svc/go.mod", "module x")
        write(self.root, "legacy/pom.xml", "<project/>")
        files = inventory.list_files(self.root)
        self.assertEqual(inventory.detect_stacks(self.root, files), ["go", "node-backend"])

    def test_detect_baas(self):
        write(self.root, "web/package.json", '{"dependencies": {"@supabase/supabase-js": "2"}}')
        files = inventory.list_files(self.root)
        self.assertEqual(inventory.detect_stacks(self.root, files), ["baas"])

    def test_detect_baas_from_migrations_and_rules(self):
        write(self.root, "supabase/migrations/001.sql", "alter table t enable row level security;")
        self.assertEqual(inventory.detect_stacks(self.root, inventory.list_files(self.root)), ["baas"])
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, ignore_errors=True)
        write(other, "firestore.rules", "rules_version = '2';")
        self.assertEqual(inventory.detect_stacks(other, inventory.list_files(other)), ["baas"])

    def test_stack_detected_glob(self):
        write(self.root, "Api.csproj", '<Project Sdk="Microsoft.NET.Sdk.Web"/>')
        self.assertTrue(inventory.stack_detected(self.root, ["Api.csproj"], patterns.STACKS["dotnet"]))


class LineHelpersTest(unittest.TestCase):
    def test_is_code_line(self):
        self.assertFalse(inventory.is_code_line("  import os"))
        self.assertFalse(inventory.is_code_line("using System.Net;"))
        self.assertTrue(inventory.is_code_line("os.system(x)"))

    def test_is_code_line_imports(self):
        for line in ("from os.path import join", "from . import views", "package main", "#include <stdio.h>",
                     "using static System.Math;", "global using System;", "using Json = System.Text.Json;",
                     "import { createClient } from '@supabase/supabase-js'"):
            self.assertFalse(inventory.is_code_line(line), line)

    def test_is_code_line_sql_and_using_declarations(self):
        for line in ("  using ((select auth.uid()) = user_id)", "  from public.members m",
                     "using var conn = new SqlConnection(cs);", "using (var r = cmd.ExecuteReader())",
                     "const m = await import('./x.js')"):
            self.assertTrue(inventory.is_code_line(line), line)

    def test_clean(self):
        self.assertEqual(inventory.clean("  a   b::c ", 10), "a b:c")
        self.assertEqual(inventory.clean("abcdef", 3), "abc")

    def test_label_for(self):
        with_label = re.search(r"get\((?P<label>'[^']*')", "get('/x')")
        without = re.search(r"@Scheduled", "@Scheduled")
        self.assertEqual(inventory.label_for(with_label), "'/x'")
        self.assertEqual(inventory.label_for(without), "@Scheduled")

    def test_matching_lines_skips_imports(self):
        text = "import subprocess\nsubprocess.run(x)\n"
        self.assertEqual([n for n, _, _ in inventory.matching_lines(text, r"subprocess")], [2])


class HitsTest(unittest.TestCase):
    def test_entry_hits_label_and_line(self):
        hits = inventory.entry_hits("C.java", 'x\n@PostMapping("/pay")\n', "java-spring", patterns.JAVA_SPRING)
        self.assertEqual(hits, [{"path": "C.java", "line": 2, "stack": "java-spring", "kind": "route",
                                 "label": '"/pay"'}])

    def test_entry_path_filter(self):
        line = "path('cards/', views.cards)"
        self.assertEqual(inventory.entry_hits("app/views.py", line, "python", patterns.PYTHON), [])
        self.assertEqual(len(inventory.entry_hits("app/urls.py", line, "python", patterns.PYTHON)), 1)

    def test_file_entries(self):
        hits = inventory.file_entries("pages/api/pay.js", "node-backend", patterns.NODE_BACKEND)
        self.assertEqual([h["kind"] for h in hits], ["route-file"])
        self.assertEqual(inventory.file_entries("lib/pay.js", "node-backend", patterns.NODE_BACKEND), [])

    def test_next_middleware_and_proxy_files(self):
        for path in ("middleware.ts", "src/middleware.ts", "apps/web/proxy.ts"):
            hits = inventory.file_entries(path, "node-backend", patterns.NODE_BACKEND)
            self.assertEqual([h["kind"] for h in hits], ["middleware"], path)

    def test_edge_function_files(self):
        hits = inventory.file_entries("supabase/functions/pay/index.ts", "baas", patterns.BAAS)
        self.assertEqual([h["kind"] for h in hits], ["edge-function"])
        self.assertEqual(inventory.file_entries("supabase/functions/_shared/index.ts", "baas", patterns.BAAS), [])

    def test_entry_hit(self):
        match = re.search(r"(?P<label>\w+)", "pay")
        self.assertEqual(inventory.entry_hit("a.ts", 3, "node-backend", "route", match),
                         {"path": "a.ts", "line": 3, "stack": "node-backend", "kind": "route", "label": "pay"})

    def test_server_module_exports_are_actions(self):
        text = ("// actions\n'use server'\n\nimport { db } from './db'\n"
                "export async function deleteCard(id) {}\nexport const renameCard = async (id, n) => {}\n")
        hits = inventory.conditional_entry_hits("app/actions.ts", text, "node-backend", patterns.NODE_BACKEND)
        self.assertEqual([(h["kind"], h["label"], h["line"]) for h in hits],
                         [("server-action", "deleteCard", 5), ("server-action", "renameCard", 6)])

    def test_exports_without_use_server_are_not_actions(self):
        text = "import x from 'y'\nexport async function helper() {}\nconst s = 'use server'\n"
        self.assertEqual(inventory.conditional_entry_hits("lib/a.ts", text, "node-backend", patterns.NODE_BACKEND),
                         [])

    def test_inline_use_server_is_one_action(self):
        text = "export default function Page() {\n  async function save(f) {\n    'use server'\n  }\n}\n"
        hits = inventory.entry_hits("app/page.tsx", text, "node-backend", patterns.NODE_BACKEND)
        self.assertEqual([(h["kind"], h["line"]) for h in hits], [("server-action", 3)])

    def test_conditional_entries_optional(self):
        self.assertEqual(inventory.conditional_entry_hits("a.go", "x", "go", patterns.GO), [])

    def test_public_secret_skips_public_client_keys(self):
        spec = patterns.WEB_FRONTEND
        for line in ("process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY", "import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY"):
            self.assertEqual(inventory.sink_hits("a.ts", line, "web-frontend", spec), [], line)
        for line in ("process.env.NEXT_PUBLIC_SUPABASE_SERVICE_KEY", "process.env.EXPO_PUBLIC_STRIPE_SECRET"):
            kinds = [h["kind"] for h in inventory.sink_hits("a.ts", line, "web-frontend", spec)]
            self.assertEqual(kinds, ["public-secret"], line)

    def test_sql_policy_lines_are_scanned(self):
        text = ("create policy p on public.cards for update\n"
                "  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');\n")
        hits = inventory.sink_hits("supabase/migrations/1.sql", text, "baas", patterns.BAAS)
        self.assertEqual([(h["kind"], h["line"]) for h in hits], [("policy", 1), ("user-metadata", 2)])

    def test_sink_hits_area(self):
        hits = inventory.sink_hits("a.py", "os.system(cmd)", "python", patterns.PYTHON)
        self.assertEqual([(h["kind"], h["area"], h["line"]) for h in hits], [("command", "injection-input", 1)])

    def test_dedupe(self):
        hits = [{"a": 1, "b": 2, "s": "x"}, {"a": 1, "b": 2, "s": "y"}, {"a": 2, "b": 2, "s": "z"}]
        self.assertEqual([h["s"] for h in inventory.dedupe(hits, ("a", "b"))], ["x", "z"])

    def test_assign_surfaces_numbers_repeats(self):
        entries = [{"path": "C.java", "kind": "route", "label": "@GetMapping"} for _ in range(2)]
        surfaces = [e["surface"] for e in inventory.assign_surfaces(entries)]
        self.assertEqual(surfaces, ["C.java#route @GetMapping", "C.java#route @GetMapping (2)"])


class ScanTest(TempRepo):
    def test_scan_file_respects_extensions(self):
        write(self.root, "a.py", "os.system(x)")
        self.assertEqual(inventory.scan_file(self.root, "a.py", ["node-backend"]), ([], []))
        _, sinks = inventory.scan_file(self.root, "a.py", ["python"])
        self.assertEqual(len(sinks), 1)

    def test_scan_repo_dedupes_shared_stacks(self):
        write(self.root, "src/a.js", "eval(input)\n")
        entries, sinks = inventory.scan_repo(self.root, ["src/a.js"], ["node-backend", "web-frontend"])
        self.assertEqual(entries, [])
        self.assertEqual([(s["kind"], s["line"]) for s in sinks], [("code", 1)])


class BuildTest(TempRepo):
    def make_repo(self):
        write(self.root, "package.json", '{"dependencies": {"express": "4"}}')
        write(self.root, "src/routes.js", "router.get('/cards/:id', h)\nexec(cmd)\n")
        write(self.root, "src/routes.test.js", "exec(cmd)\n")

    def test_build_inventory(self):
        self.make_repo()
        inv = inventory.build_inventory(self.root)
        self.assertEqual(inv["stacks"], ["node-backend"])
        self.assertEqual(inv["modules"], ["src/routes.js"])
        self.assertEqual(inv["entry_points"][0]["surface"], "src/routes.js#route '/cards/:id'")
        self.assertEqual([s["path"] for s in inv["sinks"]], ["src/routes.js"])

    def test_build_inventory_stack_override_and_only(self):
        self.make_repo()
        inv = inventory.build_inventory(self.root, ["python"], ["src/"])
        self.assertEqual((inv["stacks"], inv["entry_points"], inv["sinks"]), (["python"], [], []))

    def test_git_state(self):
        if shutil.which("git") is None:
            self.skipTest("git not installed")
        self.make_repo()
        subprocess.run(["git", "-C", self.root, "init", "-q"], check=True)
        head, dirty = inventory.git_state(self.root)
        self.assertIsNone(head)
        self.assertTrue(dirty)
        self.assertEqual(inventory.git_files(self.root), [])

    def test_summary(self):
        self.make_repo()
        result = inventory.summary(inventory.build_inventory(self.root))
        self.assertEqual(result["entry_points"], {"route": 1})
        self.assertEqual(result["sinks"], {"injection-input": 1})
        self.assertEqual(result["sink_files"], 1)


class CliTest(TempRepo):
    def run_main(self, args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            code = inventory.main(args)
        return code, out.getvalue()

    def test_normalize_prefix(self):
        self.assertEqual(inventory.normalize_prefix(".\\src\\api"), "src/api")
        self.assertEqual(inventory.normalize_prefix(".github/"), ".github/")

    def test_parse_args(self):
        options = inventory.parse_args(["repo", "--stack", "go", "--only", "src/"])
        self.assertEqual((options.stack, options.only), (["go"], ["src/"]))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(inventory.parse_args(["repo", "--stack", "cobol"]))

    def test_bad_repo_returns_2(self):
        self.assertEqual(self.run_main([os.path.join(self.root, "missing")])[0], 2)

    def test_out_writes_file(self):
        write(self.root, "go.mod", "module x")
        out_file = os.path.join(self.root, "out", "inventory.json")
        code, printed = self.run_main([self.root, "--out", out_file])
        self.assertEqual(code, 0)
        with open(out_file, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["stacks"], ["go"])
        self.assertIn('"files_scanned"', printed)


if __name__ == "__main__":
    unittest.main()
