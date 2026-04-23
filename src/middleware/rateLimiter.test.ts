/**
 * Unit tests for rateLimiter middleware.
 *
 * express-rate-limit is mocked so we can inspect the options object passed to
 * it and invoke the `handler` callback directly — no real HTTP server needed.
 */

// ── Mocks (hoisted before imports) ───────────────────────────────────────────

jest.mock("express-rate-limit", () => ({
  __esModule: true,
  default: jest.fn(() => jest.fn()),
}));

jest.mock("../config/env", () => ({
  config: {
    rateLimitWindowMs: 60_000,
    rateLimitMaxRequests: 100,
  },
}));

jest.mock("../utils/cache", () => ({
  cacheService: { increment: jest.fn() },
}));

jest.mock("../config/logger", () => ({
  logger: {
    warn: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

// ── Imports (after mocks) ─────────────────────────────────────────────────────

import { Response, NextFunction } from "express";
import rateLimit from "express-rate-limit";
import { createRateLimiter, apiKeyRateLimiter } from "./rateLimiter";
import { cacheService } from "../utils/cache";
import type { AuthRequest } from "./auth";

// ── Helpers ───────────────────────────────────────────────────────────────────

const mockRateLimit = rateLimit as jest.MockedFunction<typeof rateLimit>;

const makeRes = (): Response =>
  ({
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  }) as unknown as Response;

const makeNext = (): jest.MockedFunction<NextFunction> =>
  jest.fn() as jest.MockedFunction<NextFunction>;

/** Build a minimal AuthRequest with an attached apiKey. */
const makeApiKeyReq = (id = "key-1", rateLimit = 100): AuthRequest =>
  ({
    headers: {},
    apiKey: {
      id,
      userId: "user-1",
      organizationId: null,
      permissions: [],
      rateLimit,
    },
  }) as unknown as AuthRequest;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("createRateLimiter", () => {
  beforeEach(() => {
    mockRateLimit.mockClear();
  });

  it("defaults to IP context when no context argument is supplied", () => {
    createRateLimiter(60_000, 50);
    expect(mockRateLimit).toHaveBeenCalledTimes(1);
    const opts = mockRateLimit.mock.calls[0][0] as any;
    expect(opts.windowMs).toBe(60_000);
    expect(opts.max).toBe(50);
  });

  it("enables standard RateLimit-* headers and disables legacy X-RateLimit-* headers", () => {
    createRateLimiter(60_000, 100);
    const opts = mockRateLimit.mock.calls[0][0] as any;
    expect(opts.standardHeaders).toBe(true);
    expect(opts.legacyHeaders).toBe(false);
  });

  describe("429 handler — IP context", () => {
    it("responds with HTTP 429", () => {
      createRateLimiter(60_000, 100, "ip");
      const { handler } = mockRateLimit.mock.calls[0][0] as any;
      const res = makeRes();
      handler({}, res);
      expect(res.status).toHaveBeenCalledWith(429);
    });

    it("includes limitType 'ip' in the error body", () => {
      createRateLimiter(60_000, 100, "ip");
      const { handler } = mockRateLimit.mock.calls[0][0] as any;
      const res = makeRes();
      handler({}, res);
      expect(res.json).toHaveBeenCalledWith({
        error: {
          code: "RATE_LIMIT_EXCEEDED",
          message:
            "Too many requests from this IP address, please try again later.",
          limitType: "ip",
        },
      });
    });
  });

  describe("429 handler — api_key context", () => {
    it("responds with HTTP 429", () => {
      createRateLimiter(60_000, 100, "api_key");
      const { handler } = mockRateLimit.mock.calls[0][0] as any;
      const res = makeRes();
      handler({}, res);
      expect(res.status).toHaveBeenCalledWith(429);
    });

    it("includes limitType 'api_key' with an API-key-specific message", () => {
      createRateLimiter(60_000, 100, "api_key");
      const { handler } = mockRateLimit.mock.calls[0][0] as any;
      const res = makeRes();
      handler({}, res);
      expect(res.json).toHaveBeenCalledWith({
        error: {
          code: "RATE_LIMIT_EXCEEDED",
          message: "API key rate limit exceeded, please try again later.",
          limitType: "api_key",
        },
      });
    });

    it("does NOT mention IP in the api_key error message", () => {
      createRateLimiter(60_000, 100, "api_key");
      const { handler } = mockRateLimit.mock.calls[0][0] as any;
      const res = makeRes();
      handler({}, res);
      const body = (res.json as jest.Mock).mock.calls[0][0];
      expect(body.error.message).not.toContain("IP");
    });
  });
});

describe("apiKeyRateLimiter", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("calls next() immediately when no apiKey is attached to the request", async () => {
    const req = { headers: {} } as AuthRequest;
    const res = makeRes();
    const next = makeNext();
    await apiKeyRateLimiter(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(res.status).not.toHaveBeenCalled();
  });

  describe("cache-backed path", () => {
    it("calls next() when request count is within the limit", async () => {
      (cacheService.increment as jest.Mock).mockResolvedValue({ count: 1 });
      const req = makeApiKeyReq("key-cache-ok");
      const res = makeRes();
      const next = makeNext();
      await apiKeyRateLimiter(req, res, next);
      expect(next).toHaveBeenCalledWith();
      expect(res.status).not.toHaveBeenCalled();
    });

    it("returns 429 with limitType 'api_key' when cache count exceeds the limit", async () => {
      (cacheService.increment as jest.Mock).mockResolvedValue({ count: 101 });
      const req = makeApiKeyReq("key-cache-exceeded");
      const res = makeRes();
      const next = makeNext();
      await apiKeyRateLimiter(req, res, next);
      expect(res.status).toHaveBeenCalledWith(429);
      expect(res.json).toHaveBeenCalledWith({
        error: {
          code: "RATE_LIMIT_EXCEEDED",
          message: "API key rate limit exceeded, please try again later.",
          limitType: "api_key",
        },
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("respects a per-key rateLimit override on the apiKey object", async () => {
      // Key has a custom limit of 5; count of 6 should be rejected
      (cacheService.increment as jest.Mock).mockResolvedValue({ count: 6 });
      const req = makeApiKeyReq("key-custom-limit", 5);
      const res = makeRes();
      const next = makeNext();
      await apiKeyRateLimiter(req, res, next);
      expect(res.status).toHaveBeenCalledWith(429);
      expect(next).not.toHaveBeenCalled();
    });

    it("does NOT mention IP in the api_key error body", async () => {
      (cacheService.increment as jest.Mock).mockResolvedValue({ count: 999 });
      const req = makeApiKeyReq("key-no-ip-msg");
      const res = makeRes();
      const next = makeNext();
      await apiKeyRateLimiter(req, res, next);
      const body = (res.json as jest.Mock).mock.calls[0][0];
      expect(body.error.message).not.toContain("IP");
    });
  });

  describe("in-memory fallback path (cache unavailable)", () => {
    it("allows requests through when the fallback count is within limit", async () => {
      (cacheService.increment as jest.Mock).mockResolvedValue(null);
      const req = makeApiKeyReq("key-fallback-allow");
      const res = makeRes();
      const next = makeNext();
      await apiKeyRateLimiter(req, res, next);
      // count = 1, maxRequests = 100 → should pass
      expect(next).toHaveBeenCalledWith();
      expect(res.status).not.toHaveBeenCalled();
    });

    it("returns 429 with limitType 'api_key' when fallback count exceeds limit", async () => {
      (cacheService.increment as jest.Mock).mockResolvedValue(null);

      // Use rateLimit: 1 so the second call trips the limit
      const req = makeApiKeyReq("key-fallback-exceed", 1);
      const res1 = makeRes();
      const res2 = makeRes();
      const next1 = makeNext();
      const next2 = makeNext();

      // First call: count = 1 ≤ 1 → allowed
      await apiKeyRateLimiter(req, res1, next1);
      expect(next1).toHaveBeenCalledWith();

      // Second call: count = 2 > 1 → rejected
      await apiKeyRateLimiter(req, res2, next2);
      expect(res2.status).toHaveBeenCalledWith(429);
      expect(res2.json).toHaveBeenCalledWith({
        error: {
          code: "RATE_LIMIT_EXCEEDED",
          message: "API key rate limit exceeded, please try again later.",
          limitType: "api_key",
        },
      });
      expect(next2).not.toHaveBeenCalled();
    });
  });
});
