import { Request, Response, NextFunction } from "express";
import rateLimit from "express-rate-limit";
import { config } from "../config/env";
import { AuthRequest } from "./auth";
import { cacheService } from "../utils/cache";
import { logger } from "../config/logger";

type FallbackRateLimitEntry = {
  count: number;
  expiresAt: number;
};

/** Identifies which rate-limiting strategy produced a 429 response. */
export type LimiterContext = "ip" | "api_key";

const fallbackRateLimitStore = new Map<string, FallbackRateLimitEntry>();

const incrementFallback = (
  key: string,
  windowMs: number,
): { count: number } => {
  const now = Date.now();
  const existing = fallbackRateLimitStore.get(key);
  if (!existing || existing.expiresAt <= now) {
    const entry = { count: 1, expiresAt: now + windowMs };
    fallbackRateLimitStore.set(key, entry);
    return { count: entry.count };
  }

  existing.count += 1;
  fallbackRateLimitStore.set(key, existing);
  return { count: existing.count };
};

/**
 * Create a rate limiter with a contextual 429 response.
 *
 * @param windowMs - The time window in milliseconds.
 * @param maxRequests - Maximum number of requests allowed per window.
 * @param context - Whether this limiter tracks by `"ip"` (default) or `"api_key"`.
 *   Controls the human-readable message and the `limitType` field in the 429 body
 *   so callers can distinguish which limit was tripped.
 */
export const createRateLimiter = (
  windowMs: number,
  maxRequests: number,
  context: LimiterContext = "ip",
) => {
  const message =
    context === "ip"
      ? "Too many requests from this IP address, please try again later."
      : "API key rate limit exceeded, please try again later.";

  return rateLimit({
    windowMs,
    max: maxRequests,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req: Request, res: Response) => {
      res.status(429).json({
        error: {
          code: "RATE_LIMIT_EXCEEDED",
          message,
          limitType: context,
        },
      });
    },
  });
};

/**
 * Rate limiter for API key-based requests
 */
export const apiKeyRateLimiter = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  if (!req.apiKey) {
    return next();
  }

  const now = Date.now();
  const windowMs = config.rateLimitWindowMs;
  const maxRequests = req.apiKey.rateLimit || config.rateLimitMaxRequests;

  // Use window ID in key to ensure atomicity without complex reset logic
  const windowId = Math.floor(now / windowMs);
  const cacheKey = `rate_limit:api_key:${req.apiKey.id}:${windowId}`;

  const cached = await cacheService.increment<{ count: number }>(
    cacheKey,
    "count",
    1,
    {
      ttl: windowMs / 1000,
    },
  );

  if (!cached) {
    logger.warn("Rate limiter cache unavailable, using fallback", {
      cacheKey,
      apiKeyId: req.apiKey.id,
    });
    const fallback = incrementFallback(cacheKey, windowMs);
    if (fallback.count > maxRequests) {
      res.status(429).json({
        error: {
          code: "RATE_LIMIT_EXCEEDED",
          message: "API key rate limit exceeded, please try again later.",
          limitType: "api_key" as LimiterContext,
        },
      });
      return;
    }

    next();
    return;
  }

  if (cached.count > maxRequests) {
    res.status(429).json({
      error: {
        code: "RATE_LIMIT_EXCEEDED",
        message: "API key rate limit exceeded, please try again later.",
        limitType: "api_key" as LimiterContext,
      },
    });
    return;
  }

  next();
};

/**
 * Standard rate limiter for general endpoints
 */
export const standardRateLimiter = createRateLimiter(
  config.rateLimitWindowMs,
  config.rateLimitMaxRequests,
);
