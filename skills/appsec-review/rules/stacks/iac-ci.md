---
detect:
  - "CI pipelines: .github/workflows/*.yml, .gitlab-ci.yml, Jenkinsfile, azure-pipelines.yml, bitbucket-pipelines.yml or .circleci/config.yml"
  - "Containers: Dockerfile, Containerfile, docker-compose.yml or compose.yaml"
  - "Infrastructure as code: *.tf, *.tfvars, Kubernetes manifests (kind: Deployment, Ingress, ...), Helm charts (Chart.yaml)"
---

# Stack: CI pipelines, containers and infrastructure as code (GitHub Actions, GitLab CI, Jenkins, Docker, Kubernetes, Helm, Terraform)

Use with `configuration-supply-chain.md`, which holds the framework-neutral checks, and with the stack file of the
application the pipeline builds. A pipeline is code that runs with the repository's secrets and deploy rights:
anyone who can trigger it with input they control is an attacker with those rights.

## Entry points
- GitHub Actions: each workflow and its triggers. `pull_request_target`, `workflow_run` and `issue_comment` run
  with secrets and a write token on events any outside user can raise; `pull_request` from forks runs without
  secrets; `workflow_dispatch` and `repository_dispatch` take inputs from whoever can trigger them. Reusable
  workflows (`workflow_call`) and composite actions in `.github/actions/` inherit the caller's context.
- GitLab CI (`.gitlab-ci.yml` and `include:`), Jenkins (`Jenkinsfile`, shared libraries), Azure Pipelines,
  Bitbucket Pipelines, CircleCI: jobs that run for merge requests from forks, and parameters or variables a user
  can set when starting a run.
- What the infrastructure exposes to the internet: Kubernetes `Ingress`, `Gateway`/`HTTPRoute`, `Service` of
  type `LoadBalancer` or `NodePort`; Terraform load balancers, API gateways, Lambda function URLs, CloudFront,
  Cloud Run and App Service resources. Each is a door to the services behind it; check its auth and TLS.

## GitHub Actions
- Script injection: `${{ github.event.issue.title }}`, `...pull_request.title`, `...head_ref`, `...comment.body`,
  `...review.body`, `...pages.*.page_name`, `...commits.*.message` and `github.head_ref` inside `run:` or
  `actions/github-script` `script:` run as shell or JavaScript. Pass them through `env:` and quote the variable.
- `pull_request_target` or `workflow_run` that checks out the PR's code (`ref: ${{ github.event.pull_request.head.sha }}`,
  `refs/pull/*/merge`) and then builds, installs or runs it: the fork's code runs with secrets (pwn request).
  Artifacts downloaded in `workflow_run` from the triggering run are untrusted too.
- `permissions:` missing (the default token may be write-all on older repositories), `write-all`, or write scopes
  (`contents`, `packages`, `id-token`, `actions`, `pull-requests`) on jobs that only read.
- Actions referenced by tag or branch (`@v4`, `@main`) instead of a full commit SHA, and `docker://` images
  without a digest; self-hosted runners on public repositories; `secrets: inherit` to reusable workflows that
  don't need every secret; `toJSON(secrets)`; `ACTIONS_ALLOW_UNSECURE_COMMANDS`.
- `actions/checkout` with `persist-credentials` left on in jobs that run untrusted code; caches written by
  untrusted runs and restored by privileged ones (cache poisoning).

## GitLab CI, Jenkins and others
- GitLab: protected variables available to unprotected branches, `CI_JOB_TOKEN` scope, `include:` of remote or
  project files without a pinned `ref`, merge request pipelines from forks running in the parent project.
- Jenkins: `sh "...${params.X}"` or `${env.CHANGE_TITLE}`/`${env.BRANCH_NAME}` in Groovy-interpolated strings
  (use single quotes so the shell expands an environment variable), `@Library` without a pinned version,
  `withCredentials` blocks that echo secrets, builds of PRs from forks on agents with deploy credentials.

## Containers
- `FROM` without a digest or exact version, `latest`, images from unknown registries; no `USER` (runs as root)
  or `USER root`; `ADD` from a URL; `curl | sh`; secrets in `ENV`, `ARG` (visible in the image history) or copied
  files instead of `RUN --mount=type=secret`; `.dockerignore` missing so `.env`, `.git` or keys are copied in.
- Compose: `privileged: true`, `/var/run/docker.sock` mounted (root on the host), `network_mode: host`, database
  and admin ports published on `0.0.0.0`, secrets in `environment:`.

## Kubernetes and Helm
- Pod security: `privileged: true`, `allowPrivilegeEscalation: true` or unset, `runAsUser: 0` or no
  `runAsNonRoot`, `hostNetwork`/`hostPID`/`hostIPC`, `hostPath` mounts, added capabilities (`SYS_ADMIN`,
  `NET_ADMIN`), no `readOnlyRootFilesystem`, no resource limits.
- `kind: Secret` with values in the repository (base64 is not encryption; use Sealed Secrets, SOPS or an external
  secret store), secrets in Helm `values.yaml`, `automountServiceAccountToken` on pods that don't call the API.
- RBAC: `cluster-admin` bindings, `*` in `verbs`, `resources` or `apiGroups`, `secrets` read access, and
  `create` on pods, `pods/exec` or `rolebindings` (each is a path to cluster admin).
- No `NetworkPolicy` for namespaces holding databases or internal services; Ingress without TLS or with
  `nginx.ingress.kubernetes.io/configuration-snippet` (annotation injection on old ingress-nginx).

## Terraform
- Storage: S3 `acl = "public-read"`, `block_public_*` or `restrict_public_buckets = false`, Azure
  `allow_nested_items_to_be_public`/`public_network_access_enabled = true`, GCS `allUsers` members.
- Network: `0.0.0.0/0` or `::/0` ingress on SSH, RDP, database or admin ports; `publicly_accessible = true` on
  databases.
- IAM: `"Action": "*"`, `"service:*"` or `"Resource": "*"` on write actions, `iam:PassRole` on `*`, trust
  policies allowing any principal, GitHub OIDC roles whose `sub` condition doesn't pin the repository and branch.
- Encryption and logging: `encrypted = false`, `storage_encrypted = false`, no KMS key on sensitive data,
  `min_tls_version` below 1.2, CloudTrail or flow logs disabled, `enable_log_file_validation = false`.
- Secrets in `.tf` or committed `.tfvars`, and state files (`terraform.tfstate`) committed or stored in a public
  bucket: state holds every secret in plain text. Remote state needs encryption and locking.
- Serverless: Lambda function URLs with `authorization_type = "NONE"`, API Gateway routes with
  `authorization = "NONE"`, functions with broad roles.

## Tools
- If installed: `zizmor .` and `actionlint` for GitHub Actions, `trivy config .` or `checkov -d .` for Terraform,
  Kubernetes, Helm and Dockerfiles, `hadolint` for Dockerfiles; Semgrep packs `p/github-actions`, `p/terraform`,
  `p/dockerfile`, `p/kubernetes`.
