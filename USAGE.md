# MCP Guard 사용 가이드

> [← README로 돌아가기](README.md)

## 목차

- [설치](#설치)
- [두 가지 모드](#두-가지-모드)
- [stdio 모드](#stdio-모드-기본)
- [HTTP 모드](#http-모드)
- [CLI 옵션](#cli-옵션)
- [Claude Desktop 연동](#claude-desktop-연동)
- [Cursor IDE 연동](#cursor-ide-연동)
- [정책 파일 작성법](#정책-파일-작성법)
- [로그 이해하기](#로그-이해하기)
- [사용 시나리오](#사용-시나리오)
- [문제 해결](#문제-해결)
- [FAQ](#faq)

---

## 설치

### npm (권장)

```bash
npm install -g mcp-guard
```

### npx (설치 없이 실행)

```bash
npx mcp-guard -- npx @some/mcp-server
```

### 소스에서 빌드

```bash
git clone https://github.com/aiclude/mcp-guard.git
cd mcp-guard
npm install
npm run build
node dist/index.js --help
```

**요구 사항:** Node.js 20 이상

---

## 두 가지 모드

MCP Guard는 stdio 모드와 HTTP 모드를 지원합니다.

| 모드 | 용도 | MCP 서버 위치 |
|------|------|--------------|
| **stdio** (기본) | 로컬 MCP 서버를 자식 프로세스로 실행 | 같은 머신 |
| **http** | 원격 MCP 서버에 HTTP 리버스 프록시 | 원격 또는 로컬 |

---

## stdio 모드 (기본)

`--` 구분자를 기준으로 왼쪽은 guard 옵션, 오른쪽은 MCP 서버 명령어입니다.

```bash
mcp-guard [옵션] -- <서버 명령어> [서버 인자...]
```

### 예시

```bash
# MCP fetch 서버를 guard로 감싸기
mcp-guard -- npx @modelcontextprotocol/server-fetch

# 로컬 서버 실행
mcp-guard -- node my-mcp-server.js

# 커스텀 정책 파일 적용
mcp-guard -c my-policy.yaml -- npx @some/mcp-server

# 디버그 로그 활성화
mcp-guard --verbose -- npx @some/mcp-server

# 차단 없이 로그만 기록 (테스트용)
mcp-guard --dry-run -- npx @some/mcp-server
```

---

## HTTP 모드

`http` 서브커맨드로 HTTP 리버스 프록시를 실행합니다. Streamable HTTP (POST/GET/DELETE)와 레거시 HTTP+SSE 프로토콜을 모두 지원합니다.

```bash
mcp-guard http [옵션] --upstream <URL>
```

### 예시

```bash
# 원격 MCP 서버를 프록시
mcp-guard http --upstream http://mcp-server.internal:8080/mcp

# 포트와 호스트 지정
mcp-guard http -u http://localhost:3001/mcp -p 9090 -H 0.0.0.0

# 커스텀 정책 + 디버그 로그
mcp-guard http -u http://mcp-server:8080/mcp -c policy.yaml --verbose

# 차단 없이 관찰만
mcp-guard http -u http://mcp-server:8080/mcp --dry-run
```

### HTTP 모드 동작 원리

```
MCP Client ──HTTP POST──> mcp-guard (:9090) ──HTTP POST──> upstream MCP server
           <──SSE/JSON──                    <──SSE/JSON──
```

1. 클라이언트가 `POST /mcp`로 JSON-RPC 메시지를 보내면, guard가 인자를 검사한 뒤 upstream으로 포워딩
2. upstream의 응답(JSON 또는 SSE 스트림)을 받아서 보안 룰로 검사한 뒤 클라이언트에 전달
3. `GET /mcp`로 SSE 스트림을 요청하면, upstream SSE를 프록시하면서 각 이벤트를 실시간 검사
4. `DELETE /mcp`로 세션 종료 요청을 그대로 포워딩

### 지원하는 MCP HTTP 프로토콜

| 프로토콜 | 버전 | 지원 |
|---------|------|------|
| Streamable HTTP | 2025-03-26+ | POST, GET (SSE), DELETE |
| Legacy HTTP+SSE | 2024-11-05 | GET /sse, POST /messages |

### 포워딩되는 헤더

| 헤더 | 방향 | 설명 |
|------|------|------|
| `Mcp-Session-Id` | 양방향 | 세션 식별자 자동 전달 |
| `Mcp-Protocol-Version` | Client→Server | 프로토콜 버전 협상 |
| `Authorization` | Client→Server | 인증 토큰 전달 |
| `Last-Event-Id` | Client→Server | SSE 재연결 시 이벤트 ID |

---

## CLI 옵션

### stdio 모드 (기본)

| 옵션 | 축약 | 설명 | 기본값 |
|------|------|------|--------|
| `--config <path>` | `-c` | YAML 정책 파일 경로 | 빌트인 기본 정책 |
| `--verbose` | `-v` | 디버그 수준 로그 활성화 | `false` |
| `--fail-open` | | 정책 엔진 오류 시 트래픽 허용 (비권장) | `false` (fail-close) |
| `--dry-run` | | 차단 판정을 로그만 남기고 실제 차단하지 않음 | `false` |
| `--version` | `-V` | 버전 출력 | |
| `--help` | `-h` | 도움말 출력 | |

### http 모드 (`mcp-guard http`)

| 옵션 | 축약 | 설명 | 기본값 |
|------|------|------|--------|
| `--upstream <url>` | `-u` | upstream MCP 서버 URL **(필수)** | |
| `--port <number>` | `-p` | 리슨 포트 | `9090` |
| `--host <host>` | `-H` | 바인드 호스트 | `127.0.0.1` |
| `--config <path>` | `-c` | YAML 정책 파일 경로 | 빌트인 기본 정책 |
| `--verbose` | `-v` | 디버그 수준 로그 활성화 | `false` |
| `--fail-open` | | 정책 엔진 오류 시 트래픽 허용 (비권장) | `false` |
| `--dry-run` | | 차단 판정을 로그만 남기고 실제 차단하지 않음 | `false` |

---

## Claude Desktop 연동

Claude Desktop의 MCP 서버 설정에 mcp-guard를 wrapper로 추가합니다.

### 설정 파일 위치

| OS | 경로 |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

### 기본 설정

```json
{
  "mcpServers": {
    "fetch-guarded": {
      "command": "npx",
      "args": ["-y", "mcp-guard", "--", "npx", "-y", "@modelcontextprotocol/server-fetch"]
    }
  }
}
```

### 커스텀 정책 적용

```json
{
  "mcpServers": {
    "my-server-guarded": {
      "command": "npx",
      "args": [
        "-y", "mcp-guard",
        "-c", "/Users/you/mcp-guard-policy.yaml",
        "--",
        "npx", "-y", "@some/mcp-server"
      ]
    }
  }
}
```

### 여러 서버에 동시 적용

각 서버마다 별도의 mcp-guard 인스턴스를 설정합니다.

```json
{
  "mcpServers": {
    "fetch-guarded": {
      "command": "npx",
      "args": ["-y", "mcp-guard", "--", "npx", "-y", "@modelcontextprotocol/server-fetch"]
    },
    "github-guarded": {
      "command": "npx",
      "args": ["-y", "mcp-guard", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

### Claude Desktop에서 HTTP 모드 사용

Claude Desktop은 stdio MCP 서버만 직접 지원합니다. HTTP 모드 MCP 서버를 사용하려면 두 가지 방법이 있습니다.

**방법 1: HTTP 서버가 이미 실행 중인 경우**

별도 터미널에서 guard를 HTTP 프록시로 실행합니다.

```bash
mcp-guard http -u http://remote-mcp:8080/mcp -p 9090
```

**방법 2: stdio 모드로 로컬 HTTP 서버를 감싸기**

```json
{
  "mcpServers": {
    "my-http-server-guarded": {
      "command": "npx",
      "args": ["-y", "mcp-guard", "--", "node", "my-http-mcp-server.js"]
    }
  }
}
```

---

## Cursor IDE 연동

Cursor의 MCP 설정 파일(`.cursor/mcp.json`)에 mcp-guard를 추가합니다.

```json
{
  "mcpServers": {
    "my-server-guarded": {
      "command": "npx",
      "args": ["-y", "mcp-guard", "--", "npx", "-y", "@some/mcp-server"]
    }
  }
}
```

HTTP 모드의 원격 서버를 사용하는 경우:

```json
{
  "mcpServers": {
    "remote-guarded": {
      "command": "npx",
      "args": [
        "-y", "mcp-guard", "http",
        "-u", "http://mcp-server:8080/mcp",
        "-p", "9090"
      ]
    }
  }
}
```

---

## 정책 파일 작성법

정책 파일은 YAML 형식으로 작성합니다. 정책 파일이 없으면 빌트인 기본 정책이 적용됩니다.

### 기본 구조

```yaml
version: 1

failMode: closed    # closed(권장) | open

logging:
  level: info       # debug | info | warn | error
  destination: stderr

rules:
  - id: tool-poisoning
    enabled: true
    severity: critical
    action: block
    type: tool-poisoning
  # ...
```

### 룰 공통 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `id` | string | 룰 고유 식별자 |
| `enabled` | boolean | 활성화 여부 (기본: `true`) |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `action` | string | `block` (차단) 또는 `warn` (경고만) |
| `type` | string | 룰 타입 (아래 참조) |
| `config` | object | 룰별 세부 설정 (선택) |

### tool-poisoning 룰 설정

`tools/list` 응답에서 악성 도구 정의를 탐지합니다.

```yaml
- id: tool-poisoning
  enabled: true
  severity: critical
  action: block
  type: tool-poisoning
  config:
    checkZeroWidth: true          # 제로폭 유니코드 문자 검사
    checkInjectionPhrases: true   # 프롬프트 인젝션 구절 검사
    checkHtmlComments: true       # HTML 코멘트 숨김 검사
    checkBase64: true             # Base64 인코딩 숨김 검사
    checkShadowing: true          # 시스템 도구명 사칭 검사
    checkInstructionPatterns: true # 에이전트 조작 패턴 검사
    maxDescriptionLength: 5000    # 도구 설명 최대 길이 (0 = 무제한)
```

### argument-injection 룰 설정

`tools/call` 요청 인자에서 인젝션 패턴을 탐지합니다.

```yaml
- id: argument-injection
  enabled: true
  severity: critical
  action: block
  type: argument-injection
  config:
    checkPromptInjection: true    # 인자에서 프롬프트 인젝션 검사
```

SQL/Command/Path Traversal/XSS/Template Injection은 항상 검사됩니다 (비활성화 불가).

### data-exfiltration 룰 설정

`tools/call` 응답에서 데이터 유출 지표를 탐지합니다.

```yaml
- id: data-exfiltration
  enabled: true
  severity: high
  action: warn              # 차단하면 정상 흐름이 깨질 수 있으므로 warn 권장
  type: data-exfiltration
  config:
    checkCredentials: true
    checkPathExposure: true
    checkStackTraces: true
```

### 전체 정책 파일 예시

```yaml
version: 1
failMode: closed
logging:
  level: info
  destination: stderr
rules:
  - id: tool-poisoning
    enabled: true
    severity: critical
    action: block
    type: tool-poisoning
  - id: argument-injection
    enabled: true
    severity: critical
    action: block
    type: argument-injection
  - id: data-exfiltration
    enabled: true
    severity: high
    action: warn
    type: data-exfiltration
```

---

## 로그 이해하기

모든 로그는 stderr에 JSON 형식으로 출력됩니다. stdout은 MCP JSON-RPC 파이프이므로 절대 건드리지 않습니다.

### 시작 로그

```json
{"ts":"...","level":"info","msg":"mcp-guard starting","rules":["tool-poisoning","argument-injection","data-exfiltration"],"failMode":"closed"}
```

### 차단 로그

```json
{"ts":"...","level":"warn","msg":"BLOCKED server→client","rule":"tool-poisoning","severity":"critical","reason":"Tool \"search\": Prompt injection phrase in description"}
```

```json
{"ts":"...","level":"warn","msg":"BLOCKED client→server","rule":"argument-injection","severity":"critical","reason":"SQL Injection detected in tool \"query\" arguments (CWE-89)"}
```

### 경고 로그

```json
{"ts":"...","level":"warn","msg":"WARNING server→client","rule":"data-exfiltration","severity":"critical","reason":"Sensitive Data Exposure in tool response (CWE-200)"}
```

### Dry-run 로그

```json
{"ts":"...","level":"warn","msg":"DRY-RUN WOULD BLOCK client→server","rule":"argument-injection","severity":"critical","reason":"Command Injection detected (CWE-78)"}
```

---

## 사용 시나리오

### 시나리오 1: 새로운 MCP 서버를 처음 연결할 때

```bash
# 1단계: dry-run으로 관찰
mcp-guard --dry-run --verbose -- npx @unknown/mcp-server 2>guard.log

# 2단계: 로그 확인
cat guard.log | grep "DRY-RUN"

# 3단계: 문제가 없으면 실제 차단 모드
mcp-guard -- npx @unknown/mcp-server
```

### 시나리오 2: 프로덕션 상시 보호

```bash
cp examples/default-policy.yaml ~/mcp-guard-policy.yaml
# Claude Desktop 설정에 추가 (위 연동 섹션 참조)
```

### 시나리오 3: HTTP 보안 게이트웨이

```bash
mcp-guard http \
  -u http://internal-mcp-server:8080/mcp \
  -p 9090 -H 0.0.0.0 \
  -c /etc/mcp-guard/policy.yaml
```

### 시나리오 4: 보안 감사 로그

```bash
mcp-guard --verbose -- npx @some/mcp-server 2>audit-$(date +%Y%m%d).log
```

---

## 문제 해결

### "Failed to spawn MCP server"

`--` 뒤의 명령어가 단독으로 실행 가능한지 확인하세요.

```bash
npx @some/mcp-server
```

### 정상 도구가 차단되는 경우

1. `--dry-run --verbose`로 어떤 룰이 차단하는지 확인
2. 해당 룰의 특정 검사를 비활성화하는 정책 파일 작성
3. 또는 해당 룰의 action을 `warn`으로 변경

### 로그가 안 보이는 경우

로그는 stderr로 출력됩니다.

```bash
mcp-guard --verbose -- npx @some/mcp-server 2>/tmp/mcp-guard.log
```

### HTTP 모드 "Upstream connection failed"

```bash
curl -v http://mcp-server:8080/mcp
```

### SSE 스트림이 끊기는 경우

nginx 등 리버스 프록시가 있으면 버퍼링을 비활성화하세요.

```nginx
proxy_buffering off;
proxy_cache off;
proxy_set_header Connection '';
proxy_http_version 1.1;
```

---

## FAQ

**Q: MCP 통신 속도에 영향을 주나요?**

거의 없습니다. 동기적 패턴 매칭으로 메시지당 마이크로초 수준입니다.

**Q: 정책 파일 없이 써도 되나요?**

네. 빌트인 기본 정책이 적용됩니다 (tool-poisoning: block, argument-injection: block, data-exfiltration: warn).

**Q: fail-close가 뭔가요?**

정책 엔진 자체에 오류 발생 시 안전하게 모든 트래픽을 차단합니다. `--fail-open`으로 끌 수 있지만 비권장입니다.

**Q: Windows에서 동작하나요?**

네. `cross-spawn` 라이브러리로 Windows 호환성을 보장합니다.

**Q: HTTP(SSE) 기반 MCP 서버도 지원하나요?**

네. v0.2.0부터 Streamable HTTP와 레거시 HTTP+SSE 모두 지원합니다.

**Q: HTTP 모드에서 인증은 어떻게 처리되나요?**

`Authorization` 헤더를 upstream으로 그대로 전달합니다. guard가 토큰을 저장하거나 수정하지 않습니다.

---

> [← README로 돌아가기](README.md) · [라이선스](LICENSE.md)
