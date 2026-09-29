# AegisGap AI

**AegisGap AI** is a keyless, air-gapped, zero-trust edge-client Web Application Firewall (WAF) and SIEM engine designed to run entirely inside the user's browser context. It intercepts, sanitizes, and evaluates outbound AI prompts and inbound LLM replies locally—dropping threats before network egress occurs.

## 🚀 Core Execution Modes

### 1. Programmatic Check (Client API Integration)
Evaluate text payloads directly within your client runtime context using the native rule validation matrix.
```javascript
// Run a programmatic check manually
const evaluation = window.AISentinelCheck("Your prompt text here");
console.log(evaluation.allowed ? "Clean Payload" : "Blocked by WAF: " + evaluation.reason);
```

### 2. Local Proxy Guard (Interceptor Mode)
Hooks into global network entrypoints to inspect and intercept outgoing traffic bound for upstream AI providers (OpenAI, Anthropic, Gemini) right before it leaves the machine.
```javascript
// Initialize Global Interceptor Guard
AISentinel.guard();
```

### 3. Integrated Diagnostics & Self-Test
Runs the foundational rules catalogue against weaponized reverse shells and indirect injection strings to check browser/runtime environment capabilities.
```javascript
// Run the built-in validation framework
const suite = AISentinel.selfTest();
console.log("Diagnostic status:", suite.passed);
```

## 📋 Finding Policy Validation States

- **ALLOW:** Clean payload compliance check validation passed.
- **WARN:** Triggered minor sensitivity threshold metrics; payload passed but flagged in SIEM audit log.
- **BLOCK:** Direct structural threat confirmed. Dropped locally with a synthetic `403 Forbidden` network response.
