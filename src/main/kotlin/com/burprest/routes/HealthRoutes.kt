package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.HealthResponse
import com.burprest.models.VersionResponse
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.healthRoutes(startTime: Long) {
    get("/health") {
        val uptime = (System.currentTimeMillis() - startTime) / 1000
        call.respond(
            ApiResponse.ok(
                HealthResponse(
                    status = "ok",
                    version = "0.1.0",
                    uptime = uptime,
                )
            )
        )
    }

    get("/version") {
        call.respond(
            ApiResponse.ok(
                VersionResponse(
                    version = "0.1.0",
                    name = "burp-rest-extension",
                )
            )
        )
    }

    get("/docs") {
        call.respondText(OPENAPI_SPEC, io.ktor.http.ContentType.Application.Json)
    }
}

private val OPENAPI_SPEC = """
{
  "openapi": "3.0.3",
  "info": {
    "title": "Burp REST Extension API",
    "version": "0.1.0",
    "description": "REST API exposing Burp Suite Montoya API via HTTP on port 8089"
  },
  "servers": [{"url": "http://127.0.0.1:8089"}],
  "paths": {
    "/health": {
      "get": {"summary": "Health check", "tags": ["System"], "responses": {"200": {"description": "Health status with uptime"}}}
    },
    "/version": {
      "get": {"summary": "Version info", "tags": ["System"], "responses": {"200": {"description": "Extension version"}}}
    },
    "/docs": {
      "get": {"summary": "OpenAPI spec (this document)", "tags": ["System"], "responses": {"200": {"description": "OpenAPI JSON"}}}
    },
    "/proxy/history": {
      "get": {"summary": "Get proxy history entries", "tags": ["Proxy"], "parameters": [
        {"name": "offset", "in": "query", "schema": {"type": "integer"}},
        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
        {"name": "search", "in": "query", "schema": {"type": "string"}}
      ]}
    },
    "/proxy/history/{id}": {
      "get": {"summary": "Get single proxy history entry", "tags": ["Proxy"]}
    },
    "/proxy/intercept": {
      "get": {"summary": "Get intercept status", "tags": ["Proxy"]}
    },
    "/proxy/intercept/enable": {
      "post": {"summary": "Enable request interception", "tags": ["Proxy"]}
    },
    "/proxy/intercept/disable": {
      "post": {"summary": "Disable request interception", "tags": ["Proxy"]}
    },
    "/proxy/websocket/history": {
      "get": {"summary": "Get WebSocket proxy history", "tags": ["Proxy"]}
    },
    "/repeater/send": {
      "post": {"summary": "Send HTTP request via Burp", "tags": ["Repeater"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"request": {"type": "object"}, "requestId": {"type": "integer"}, "modifications": {"type": "object"}}}}}}}
    },
    "/repeater/send/batch": {
      "post": {"summary": "Send multiple requests", "tags": ["Repeater"]}
    },
    "/repeater/tab/create": {
      "post": {"summary": "Create Repeater tab in Burp UI", "tags": ["Repeater"]}
    },
    "/session/set": {
      "post": {"summary": "Set session cookies and headers", "tags": ["Session"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"cookies": {"type": "object"}, "headers": {"type": "object"}, "name": {"type": "string"}}}}}}}
    },
    "/session/get": {
      "get": {"summary": "Get current session info", "tags": ["Session"]}
    },
    "/session/clear": {
      "delete": {"summary": "Clear session", "tags": ["Session"]}
    },
    "/session/send": {
      "post": {"summary": "Send request with session cookies/headers auto-injected", "tags": ["Session"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["url"], "properties": {"method": {"type": "string", "default": "GET"}, "url": {"type": "string"}, "body": {"type": "string"}, "extraHeaders": {"type": "object"}}}}}}}
    },
    "/session/send/batch": {
      "post": {"summary": "Batch send with session", "tags": ["Session"]}
    },
    "/session/cookie-jar": {
      "get": {"summary": "Get auto-captured cookies from Set-Cookie headers", "tags": ["Session"]},
      "delete": {"summary": "Clear cookie jar", "tags": ["Session"]}
    },
    "/intruder/attack/create": {
      "post": {"summary": "Create an intruder attack", "tags": ["Intruder"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"request": {"type": "object"}, "requestId": {"type": "integer"}, "attackType": {"type": "string"}, "positions": {"type": "array"}, "payloads": {"type": "object"}, "options": {"type": "object"}}}}}}}
    },
    "/intruder/attack/{id}/start": {
      "post": {"summary": "Start attack execution", "tags": ["Intruder"]}
    },
    "/intruder/attack/{id}/status": {
      "get": {"summary": "Get attack status (includes isComplete flag)", "tags": ["Intruder"]}
    },
    "/intruder/attack/{id}/results": {
      "get": {"summary": "Get attack results with pagination", "tags": ["Intruder"], "parameters": [
        {"name": "offset", "in": "query", "schema": {"type": "integer"}},
        {"name": "limit", "in": "query", "schema": {"type": "integer"}}
      ]}
    },
    "/intruder/attack/{id}/pause": {
      "post": {"summary": "Pause attack", "tags": ["Intruder"]}
    },
    "/intruder/attack/{id}/resume": {
      "post": {"summary": "Resume paused attack", "tags": ["Intruder"]}
    },
    "/intruder/attack/{id}/stop": {
      "post": {"summary": "Stop attack", "tags": ["Intruder"]}
    },
    "/intruder/quick-fuzz": {
      "post": {"summary": "Quick fuzz a parameter with baseline anomaly detection", "tags": ["Intruder"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["param", "payloads"], "properties": {"request": {"type": "object"}, "requestId": {"type": "integer"}, "param": {"type": "string"}, "payloads": {"type": "array", "items": {"type": "string"}}, "options": {"type": "object"}}}}}}}
    },
    "/scanner/crawl": {
      "post": {"summary": "Start crawl (Burp Pro only)", "tags": ["Scanner"]}
    },
    "/scanner/audit": {
      "post": {"summary": "Start active audit (Burp Pro only)", "tags": ["Scanner"]}
    },
    "/scanner/crawl-and-audit": {
      "post": {"summary": "Start crawl + audit (Burp Pro only)", "tags": ["Scanner"]}
    },
    "/scanner/{id}/status": {
      "get": {"summary": "Get scan status", "tags": ["Scanner"]}
    },
    "/scanner/{id}/issues": {
      "get": {"summary": "Get scan issues", "tags": ["Scanner"]}
    },
    "/scanner/{id}/pause": {
      "post": {"summary": "Pause scan", "tags": ["Scanner"]}
    },
    "/scanner/{id}/resume": {
      "post": {"summary": "Resume scan", "tags": ["Scanner"]}
    },
    "/scanner/{id}/stop": {
      "post": {"summary": "Stop scan", "tags": ["Scanner"]}
    },
    "/scanner/issue-definitions": {
      "get": {"summary": "Get issue definitions from sitemap", "tags": ["Scanner"]}
    },
    "/target/sitemap": {
      "get": {"summary": "Get sitemap entries", "tags": ["Target"]}
    },
    "/target/scope": {
      "get": {"summary": "Get scope URLs (includes/excludes)", "tags": ["Target"]},
      "post": {"summary": "Set scope (replace includes/excludes)", "tags": ["Target"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "properties": {"includes": {"type": "array", "items": {"type": "string"}}, "excludes": {"type": "array", "items": {"type": "string"}}}}}}}}
    },
    "/target/scope/add": {
      "post": {"summary": "Add URL to scope", "tags": ["Target"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["url"], "properties": {"url": {"type": "string"}}}}}}}
    },
    "/target/scope/remove": {
      "post": {"summary": "Remove URL from scope", "tags": ["Target"], "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["url"], "properties": {"url": {"type": "string"}}}}}}}
    },
    "/target/scope/check": {
      "get": {"summary": "Check if URL is in scope", "tags": ["Target"], "parameters": [{"name": "url", "in": "query", "required": true, "schema": {"type": "string"}}]}
    },
    "/collaborator/generate": {
      "post": {"summary": "Generate Burp Collaborator payload", "tags": ["Collaborator"]}
    },
    "/collaborator/poll": {
      "get": {"summary": "Poll for Collaborator interactions", "tags": ["Collaborator"]}
    },
    "/decoder/encode": {
      "post": {"summary": "Encode data (base64, url, html, hex, gzip)", "tags": ["Decoder"]}
    },
    "/decoder/decode": {
      "post": {"summary": "Decode data", "tags": ["Decoder"]}
    },
    "/decoder/hash": {
      "post": {"summary": "Hash data (md5, sha1, sha256, sha512)", "tags": ["Decoder"]}
    },
    "/decoder/smart-decode": {
      "post": {"summary": "Auto-detect and decode", "tags": ["Decoder"]}
    },
    "/config/project": {
      "get": {"summary": "Get project config", "tags": ["Config"]},
      "put": {"summary": "Update project config", "tags": ["Config"]}
    },
    "/config/user": {
      "get": {"summary": "Get user config", "tags": ["Config"]},
      "put": {"summary": "Update user config", "tags": ["Config"]}
    },
    "/extensions": {
      "get": {"summary": "List loaded extensions", "tags": ["Config"]}
    },
    "/history": {
      "get": {"summary": "Search request history (DB-backed)", "tags": ["History"], "parameters": [
        {"name": "host", "in": "query", "schema": {"type": "string"}},
        {"name": "method", "in": "query", "schema": {"type": "string"}},
        {"name": "statusCode", "in": "query", "schema": {"type": "integer"}},
        {"name": "source", "in": "query", "schema": {"type": "string"}},
        {"name": "search", "in": "query", "schema": {"type": "string"}},
        {"name": "since", "in": "query", "schema": {"type": "string"}},
        {"name": "until", "in": "query", "schema": {"type": "string"}},
        {"name": "page", "in": "query", "schema": {"type": "integer"}},
        {"name": "pageSize", "in": "query", "schema": {"type": "integer"}}
      ]},
      "delete": {"summary": "Clear all history and sitemap", "tags": ["History"]}
    },
    "/history/{id}": {
      "get": {"summary": "Get single history entry by ID", "tags": ["History"]}
    },
    "/history/{id}/replay": {
      "post": {"summary": "Replay a stored request and compare responses", "tags": ["History"]}
    },
    "/history/sitemap": {
      "get": {"summary": "Auto-built sitemap from all API requests", "tags": ["History"], "parameters": [
        {"name": "host", "in": "query", "schema": {"type": "string"}}
      ]}
    }
  }
}
""".trimIndent()
