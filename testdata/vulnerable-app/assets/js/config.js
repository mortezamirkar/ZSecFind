/**
 * Application configuration — DO NOT commit to git (but someone did)
 */
const AppConfig = {
  env: "production",
  version: "2.4.1",

  api: {
    baseUrl: "https://api.acme-shop.io",
    timeout: 30000,
    // internal staging fallback
    fallback: "http://10.0.42.15:8080/api",
  },

  auth: {
    jwtSecret: "super-secret-jwt-key-change-me-in-prod",
    tokenEndpoint: "/oauth/token",
  },

  integrations: {
  stripe_private: "sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    sendgrid_api_key: "SG.xxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    google_maps_api_key: "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    github_token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    aws_access_key_id: "AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    datadog_api_key: "dd000000000000000000000000000000",
    slack_webhook: "https://hooks.slack.com/services/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",
    gitlab_token: "glpat-xxxxxxxxxxxxxxxxxxxx",
  },

  database: {
    host: "db.acme-shop.internal",
    user: "acme_admin",
    password: "P@ssw0rd!2024#prod",
    connection: "mysql://acme_admin:P@ssw0rd!2024#prod@192.168.1.50:3306/acme_shop",
  },

  features: {
    enableBeta: true,
    analyticsId: "UA-12345678-1",
  },
};

// Bearer token left in client bundle (common mistake)
const SERVICE_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// Basic auth credentials
const BASIC_AUTH = "Basic YWRtaW46c3VwZXJzZWNyZXQxMjM=";

if (typeof module !== "undefined") {
  module.exports = { AppConfig, SERVICE_TOKEN };
}
