import IORedis from "ioredis";
import { Queue, ConnectionOptions } from "bullmq";

let connection: IORedis | null = null;
let redisAvailable = false;

function getRedisUrl(): string {
  return process.env.REDIS_URL || process.env.BULLMQ_REDIS_URL || "redis://localhost:6379";
}

function getConnectionOptions(): ConnectionOptions {
  const url = getRedisUrl();
  try {
    const parsed = new URL(url);
    return {
      host: parsed.hostname,
      port: parseInt(parsed.port || "6379"),
      password: parsed.password || undefined,
      username: parsed.username || undefined,
      maxRetriesPerRequest: null,
    };
  } catch {
    return {
      host: "localhost",
      port: 6379,
      maxRetriesPerRequest: null,
    };
  }
}

export function getRedisConnection(): IORedis | null {
  if (connection) return connection;

  try {
    const url = getRedisUrl();
    connection = new IORedis(url, {
      lazyConnect: true,
      enableOfflineQueue: false,
      connectTimeout: 3000,
      maxRetriesPerRequest: null,
    } as never);

    connection.on("error", () => {
      redisAvailable = false;
    });

    connection.on("connect", () => {
      redisAvailable = true;
    });

    return connection;
  } catch {
    return null;
  }
}

export function isRedisAvailable(): boolean {
  return redisAvailable;
}

export function createQueue<T = Record<string, unknown>>(name: string): Queue<T> | null {
  const conn = getRedisConnection();
  if (!conn) return null;

  return new Queue<T>(name, {
    connection: conn,
    defaultJobOptions: {
      removeOnComplete: { count: 1000 },
      removeOnFail: { count: 5000 },
      attempts: 3,
      backoff: { type: "exponential", delay: 2000 },
    },
  });
}

export { Queue };
