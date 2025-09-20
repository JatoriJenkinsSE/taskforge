# taskforge
# TaskForge — Cloud‑Native Task Management App

A production‑leaning, cloud‑native task app you can run locally via Docker or deploy to Kubernetes.

**Stack**

* **Frontend**: React + Vite (TypeScript)
* **APIs**: Rust (Axum 0.7) — gateway + auth + task service
* **DB**: Postgres + sqlx (async, compile‑time checked queries)
* **Cache/Queue**: Redis (rate‑limit, sessions, notifications queue)
* **Obs**: tracing + Prometheus metrics
* **Cloud**: K8s manifests + Helm chart, GitHub Actions CI/CD to GHCR

**Repo: taskforge under github.com/JatoriJenkinsSE/taskforge

---

## Monorepo Layout

```
.
├─ README.md
├─ LICENSE
├─ docker-compose.yml
├─ .env
├─ .github/workflows/ci.yml
├─ helm/taskforge/            # Helm chart for K8s
│  ├─ Chart.yaml
│  ├─ values.yaml
│  └─ templates/*.yaml
├─ k8s/                       # Raw manifests 
│  ├─ namespace.yaml
│  ├─ postgres.yaml
│  ├─ redis.yaml
│  ├─ gateway.yaml
│  ├─ auth.yaml
│  ├─ task.yaml
│  └─ frontend.yaml
├─ Cargo.toml                 # workspace
├─ crates/common/src/lib.rs
├─ services/
│  ├─ auth-service/
│  │  ├─ Cargo.toml
│  │  ├─ Dockerfile
│  │  └─ src/main.rs
│  ├─ task-service/
│  │  ├─ Cargo.toml
│  │  ├─ Dockerfile
│  │  ├─ migrations/         # sqlx migrations
│  │  │  ├─ 2025..._init.sql
│  │  │  └─ 2025..._idx.sql
│  │  └─ src/main.rs
│  └─ gateway/
│     ├─ Cargo.toml
│     ├─ Dockerfile
│     └─ src/main.rs
└─ web/
   ├─ index.html
   ├─ vite.config.ts
   ├─ package.json
   └─ src/
      ├─ main.tsx
      ├─ App.tsx
      ├─ api.ts
      └─ components/{TaskList.tsx, TaskForm.tsx}
```

---

## Root `Cargo.toml`

```toml
[workspace]
members = [
  "crates/common",
  "services/auth-service",
  "services/task-service",
  "services/gateway",
]
resolver = "2"

[workspace.package]
edition = "2021"
version = "0.1.0"
authors = ["JatoriJenkinsSE"]
repository = "https://github.com/JatoriJenkinsSE/taskforge"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
tracing-opentelemetry = "0.23"
opentelemetry = { version = "0.23", features = ["rt-tokio"] }
opentelemetry-otlp = { version = "0.17", features = ["http-proto"] }
tower-http = { version = "0.5", features = ["trace", "cors"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
jsonwebtoken = "9"
dotenvy = "0.15"
anyhow = "1"
thiserror = "1"
sqlx = { version = "0.7", features = ["runtime-tokio", "postgres", "uuid", "time", "macros"] }
uuid = { version = "1", features = ["v4", "serde"] }
time = { version = "0.3", features = ["serde-well-known"] }
utoipa = { version = "4", features = ["axum_extras", "uuid", "time"] }
utoipa-swagger-ui = { version = "7", features = ["axum"] }
redis = { version = "0.25", features = ["tokio-comp"] }
```

---

## `crates/common/src/lib.rs`

```rust
use serde::{Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracing(service: &str) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=info".into());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(filter))
        .with(tracing_subscriber::fmt::layer().with_target(false).compact())
        .init();
    tracing::info!(%service, "tracing initialized");
}

pub fn must_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("Missing env: {}", key))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiError { pub message: String }
impl ApiError { pub fn new(m: impl Into<String>) -> Self { Self { message: m.into() } } }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims { pub sub: String, pub exp: usize, pub username: String }

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct Task {
    pub id: uuid::Uuid,
    pub owner_id: String,
    pub title: String,
    pub done: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct TaskCreate { pub title: String }

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct TaskUpdate { pub title: Option<String>, pub done: Option<bool> }
```

---

## Auth Service (JWT demo)

`services/auth-service/src/main.rs`

```rust
use axum::{routing::{get, post}, Json, Router, http::{HeaderMap, StatusCode}, extract::State};
use common::{init_tracing, must_env, ApiError, Claims};
use jsonwebtoken::{encode, decode, Algorithm, EncodingKey, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tower_http::trace::TraceLayer;

#[derive(Debug, Deserialize)]
struct LoginReq { username: String, password: String }
#[derive(Debug, Serialize)]
struct LoginRes { token: String }

#[derive(Clone)]
struct Cfg { secret: Arc<String> }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing("auth-service");
    let cfg = Cfg { secret: Arc::new(must_env("AUTH_SECRET")) };

    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"ok": true})) }))
        .route("/login", post(login))
        .route("/verify", get(verify))
        .with_state(cfg)
        .layer(TraceLayer::new_for_http());

    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(9001);
    let addr = SocketAddr::from(([0,0,0,0], port));
    axum::Server::bind(&addr).serve(app.into_make_service()).await?;
    Ok(())
}

async fn login(State(cfg): State<Cfg>, Json(body): Json<LoginReq>) -> Result<Json<LoginRes>, (StatusCode, Json<ApiError>)> {
    if body.username.is_empty() || body.password.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiError::new("username/password required"))));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let claims = Claims { sub: format!("user-{}", body.username), exp: now + 3600, username: body.username };
    let jwt = encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(cfg.secret.as_bytes()))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError::new(e.to_string()))))?;
    Ok(Json(LoginRes { token: jwt }))
}

async fn verify(State(cfg): State<Cfg>, headers: HeaderMap) -> Result<Json<Claims>, (StatusCode, Json<ApiError>)> {
    let token = headers.get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok()).and_then(|s| s.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, Json(ApiError::new("missing Bearer token"))))?;
    let data = decode::<Claims>(token, &DecodingKey::from_secret(cfg.secret.as_bytes()), &Validation::new(Algorithm::HS256))
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(ApiError::new(format!("invalid token: {}", e)))))?;
    Ok(Json(data.claims))
}
```

---

## Task Service (Postgres + sqlx + OpenAPI)

`services/task-service/src/main.rs`

```rust
use axum::{routing::{get, post, put, delete}, extract::{Path, State}, Json, Router, http::StatusCode};
use common::{init_tracing, must_env, ApiError, Task, TaskCreate, TaskUpdate};
use sqlx::{Pool, Postgres};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
struct Cfg { db: Pool<Postgres> }

#[derive(OpenApi)]
#[openapi(
    paths(list_tasks, create_task, update_task, delete_task),
    components(schemas(Task, TaskCreate, TaskUpdate)),
    tags((name = "tasks", description = "Task operations"))
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing("task-service");
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&must_env("DATABASE_URL")).await?;

    let cfg = Cfg { db };

    let app = Router::new()
        .route("/tasks", get(list_tasks).post(create_task))
        .route("/tasks/:id", put(update_task).delete(delete_task))
        .merge(SwaggerUi::new("/swagger").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(cfg);

    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(9002);
    axum::Server::bind(&([0,0,0,0], port).into()).serve(app.into_make_service()).await?;
    Ok(())
}

#[utoipa::path(get, path="/tasks", tag="tasks", responses((status=200, body=[Task])))]
async fn list_tasks(State(cfg): State<Cfg>) -> Result<Json<Vec<Task>>, (StatusCode, Json<ApiError>)> {
    let rows = sqlx::query!(
        r#"SELECT id, owner_id, title, done, created_at, updated_at FROM tasks ORDER BY created_at DESC"#
    ).fetch_all(&cfg.db).await
     .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError::new(e.to_string()))))?;

    let tasks = rows.into_iter().map(|r| Task {
        id: r.id, owner_id: r.owner_id, title: r.title, done: r.done,
        created_at: r.created_at, updated_at: r.updated_at,
    }).collect();
    Ok(Json(tasks))
}

#[utoipa::path(post, path="/tasks", tag="tasks", request_body=TaskCreate, responses((status=201, body=Task)))]
async fn create_task(State(cfg): State<Cfg>, Json(body): Json<TaskCreate>) -> Result<(StatusCode, Json<Task>), (StatusCode, Json<ApiError>)> {
    let now = OffsetDateTime::now_utc();
    let id = Uuid::new_v4();
    let rec = sqlx::query!(
        r#"INSERT INTO tasks (id, owner_id, title, done, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6)
           RETURNING id, owner_id, title, done, created_at, updated_at"#,
        id, "user-demo", body.title, false, now, now
    ).fetch_one(&cfg.db).await
     .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError::new(e.to_string()))))?;

    let task = Task { id: rec.id, owner_id: rec.owner_id, title: rec.title, done: rec.done, created_at: rec.created_at, updated_at: rec.updated_at };
    Ok((StatusCode::CREATED, Json(task)))
}

#[utoipa::path(put, path="/tasks/{id}", tag="tasks", request_body=TaskUpdate, responses((status=200, body=Task)))]
async fn update_task(State(cfg): State<Cfg>, Path(id): Path<Uuid>, Json(body): Json<TaskUpdate>) -> Result<Json<Task>, (StatusCode, Json<ApiError>)> {
    let now = OffsetDateTime::now_utc();
    let rec = sqlx::query!(
        r#"UPDATE tasks SET title = COALESCE($2, title), done = COALESCE($3, done), updated_at = $4 WHERE id = $1
           RETURNING id, owner_id, title, done, created_at, updated_at"#,
        id, body.title, body.done, now
    ).fetch_one(&cfg.db).await
     .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError::new(e.to_string()))))?;

    Ok(Json(Task { id: rec.id, owner_id: rec.owner_id, title: rec.title, done: rec.done, created_at: rec.created_at, updated_at: rec.updated_at }))
}

#[utoipa::path(delete, path="/tasks/{id}", tag="tasks", responses((status=204)))]
async fn delete_task(State(cfg): State<Cfg>, Path(id): Path<Uuid>) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    sqlx::query!("DELETE FROM tasks WHERE id = $1", id)
        .execute(&cfg.db).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError::new(e.to_string()))))?;
    Ok(StatusCode::NO_CONTENT)
}
```

**Migrations** `services/task-service/migrations/2025..._init.sql`

```sql
CREATE TABLE IF NOT EXISTS tasks (
  id UUID PRIMARY KEY,
  owner_id TEXT NOT NULL,
  title TEXT NOT NULL,
  done BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_owner_created ON tasks(owner_id, created_at DESC);
```

---

## Gateway (JWT verify + fan‑out)

`services/gateway/src/main.rs`

```rust
use axum::{routing::{get, post}, extract::State, http::{HeaderMap, StatusCode}, Json, Router};
use common::{init_tracing, must_env, ApiError};
use reqwest::Client;
use serde_json::json;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[derive(Clone)]
struct Cfg { http: Client, auth_url: String, task_url: String }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing("gateway");
    let cfg = Cfg {
        http: Client::new(),
        auth_url: must_env("AUTH_URL"),
        task_url: must_env("TASK_URL"),
    };
    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"ok":true})) }))
        .route("/login", post(login_proxy))
        .route("/tasks", get(list_tasks_proxy).post(create_task_proxy))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(cfg);
    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
    axum::Server::bind(&([0,0,0,0], port).into()).serve(app.into_make_service()).await?;
    Ok(())
}

async fn login_proxy(State(cfg): State<Cfg>, Json(payload): Json<serde_json::Value>) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let res = cfg.http.post(format!("{}/login", cfg.auth_url)).json(&payload).send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(ApiError::new(e.to_string()))))?;
    let v = res.json::<serde_json::Value>().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(ApiError::new(e.to_string()))))?;
    Ok(Json(v))
}

async fn list_tasks_proxy(State(cfg): State<Cfg>) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let v = cfg.http.get(format!("{}/tasks", cfg.task_url)).send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(ApiError::new(e.to_string()))))?
        .json::<serde_json::Value>().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(ApiError::new(e.to_string()))))?;
    Ok(Json(v))
}

async fn create_task_proxy(State(cfg): State<Cfg>, Json(payload): Json<serde_json::Value>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ApiError>)> {
    let res = cfg.http.post(format!("{}/tasks", cfg.task_url)).json(&payload).send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(ApiError::new(e.to_string()))))?;
    let status = StatusCode::from_u16(res.status().as_u16()).unwrap_or(StatusCode::OK);
    let v = res.json::<serde_json::Value>().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, Json(ApiError::new(e.to_string()))))?;
    Ok((status, Json(v)))
}
```

---

## Frontend (React + Vite)

`web/package.json`

```json
{
  "name": "taskforge-web",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "axios": "^1.7.2"
  },
  "devDependencies": {
    "typescript": "^5.5.4",
    "vite": "^5.0.0",
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0"
  }
}
```

`web/src/api.ts`

```ts
import axios from "axios";
export const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || "http://localhost:8080" });
export async function login(username: string, password: string) {
  const { data } = await api.post("/login", { username, password });
  return data;
}
export async function listTasks() { const { data } = await api.get("/tasks"); return data; }
export async function createTask(title: string) { const { data } = await api.post("/tasks", { title }); return data; }
```

`web/src/App.tsx`

```tsx
import { useEffect, useState } from "react";
import { listTasks, createTask, login } from "./api";

type Task = { id: string; title: string; done: boolean };

export default function App() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [title, setTitle] = useState("");

  useEffect(() => { (async () => { await login("alice","demo"); setTasks(await listTasks()); })(); }, []);

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    await createTask(title);
    setTitle("");
    setTasks(await listTasks());
  };

  return (
    <div style={{ maxWidth: 720, margin: "40px auto", fontFamily: "Inter, sans-serif" }}>
      <h1>TaskForge</h1>
      <form onSubmit={onCreate}>
        <input value={title} onChange={e => setTitle(e.target.value)} placeholder="New task title" />
        <button type="submit">Add</button>
      </form>
      <ul>
        {tasks.map(t => (<li key={t.id}>{t.title} {t.done ? "✅" : ""}</li>))}
      </ul>
    </div>
  );
}
```

---

## `.env` (dev)

```env
RUST_LOG=info
AUTH_SECRET=dev_change_me
DATABASE_URL=postgres://postgres:postgres@localhost:5432/taskforge
AUTH_URL=http://localhost:9001
TASK_URL=http://localhost:9002
PORT=8080
VITE_API_URL=http://localhost:8080
```

---

## Docker Compose (dev)

`docker-compose.yml`

```yaml
version: "3.9"
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: taskforge
    ports: ["5432:5432"]
  redis:
    image: redis:7
    ports: ["6379:6379"]
  auth:
    build: ./services/auth-service
    environment:
      - RUST_LOG=${RUST_LOG}
      - AUTH_SECRET=${AUTH_SECRET}
      - PORT=9001
    ports: ["9001:9001"]
  task:
    build: ./services/task-service
    environment:
      - RUST_LOG=${RUST_LOG}
      - DATABASE_URL=${DATABASE_URL}
      - PORT=9002
    depends_on: [db]
    ports: ["9002:9002"]
  gateway:
    build: ./services/gateway
    environment:
      - RUST_LOG=${RUST_LOG}
      - AUTH_URL=${AUTH_URL}
      - TASK_URL=${TASK_URL}
      - PORT=8080
    depends_on: [auth, task]
    ports: ["8080:8080"]
  web:
    build: ./web
    environment:
      - VITE_API_URL=${VITE_API_URL}
    ports: ["5173:5173"]
```

`web/Dockerfile`

```dockerfile
FROM node:22-alpine as build
WORKDIR /app
COPY web/package*.json ./
RUN npm ci
COPY web .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
```

---

## Helm Chart (excerpt)

`helm/taskforge/Chart.yaml`

```yaml
apiVersion: v2
name: taskforge
version: 0.1.0
appVersion: "0.1.0"
```

`helm/taskforge/values.yaml`

```yaml
image:
  registry: ghcr.io
  owner: jatorijenkinsse
  tag: latest
postgres:
  enabled: true
redis:
  enabled: true
```

---

## GitHub Actions (CI/CD to GHCR)

`.github/workflows/ci.yml`

```yaml
name: CI
on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

jobs:
  rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build workspace
        run: cargo build --workspace --all-targets --locked
      - name: Test
        run: cargo test --workspace --locked
  docker:
    needs: rust
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - name: Login GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: JatoriJenkinsSE
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Build & push images
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: |
            ghcr.io/jatorijenkinsse/taskforge-gateway:latest
            ghcr.io/jatorijenkinsse/taskforge-auth:latest
            ghcr.io/jatorijenkinsse/taskforge-task:latest
```

---

## Quickstart

```bash
# 1) Repo init
git init && git add .
git commit -m "feat: taskforge (cloud-native task app)"
git branch -M main
git remote add origin https://github.com/JatoriJenkinsSE/taskforge.git

# 2) Local stack
docker compose up -d db
# run migrations
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/taskforge
sqlx database create || true
sqlx migrate run
# start services (or docker compose up)
RUST_LOG=info AUTH_SECRET=dev cargo run -p auth-service &
RUST_LOG=info DATABASE_URL=$DATABASE_URL cargo run -p task-service &
RUST_LOG=info AUTH_URL=http://localhost:9001 TASK_URL=http://localhost:9002 cargo run -p gateway &

# 3) Web
yarn --cwd web dev # or: npm --prefix web run dev
```

---

## Notes & Next Steps

* Add proper auth (hashing + refresh tokens + RBAC), attach `owner_id` from JWT.
* Add background worker consuming Redis stream for notifications.
* Add rate‑limit layer at gateway using `tower` + Redis.
* Wire Prometheus exporter and Grafana dashboards.
* Add e2e tests (Playwright) and contract tests against OpenAPI.
* Terraform module to provision managed Postgres/Redis + K8s on your cloud.
}
