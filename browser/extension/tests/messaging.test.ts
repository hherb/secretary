import { describe, it, expect } from "vitest";

import {
  collectQuery,
  isQueryRequest,
  queryHost,
  HOST_NAME,
  type PortLike,
  type RuntimeLike,
} from "../src/messaging";

describe("isQueryRequest", () => {
  it("accepts a well-formed request", () => {
    expect(isQueryRequest({ kind: "secretary-query" })).toBe(true);
  });
  it("rejects wrong kind / non-objects", () => {
    expect(isQueryRequest({ kind: "other" })).toBe(false);
    expect(isQueryRequest(null)).toBe(false);
    expect(isQueryRequest("secretary-query")).toBe(false);
    expect(isQueryRequest(undefined)).toBe(false);
  });
});

describe("collectQuery", () => {
  it("sets https=true for an https page, frame_origin == top_origin", () => {
    const q = collectQuery({ origin: "https://example.com", protocol: "https:" });
    expect(q).toEqual({
      kind: "secretary-query",
      top_origin: "https://example.com",
      frame_origin: "https://example.com",
      https: true,
    });
  });
  it("sets https=false for an http page", () => {
    const q = collectQuery({ origin: "http://example.com", protocol: "http:" });
    expect(q.https).toBe(false);
  });
});

/**
 * Build a fake `RuntimeLike` whose port, on `postMessage`, drives either a reply
 * (`onMessage`) or a disconnect (`onDisconnect`), so `queryHost`'s promise
 * lifecycle can be tested without a browser.
 */
function fakeRuntime(opts: {
  reply?: unknown;
  disconnect?: boolean;
  lastError?: { message?: string };
}): { runtime: RuntimeLike; calls: { connected: number; posted: unknown[]; disconnected: number } } {
  const calls = { connected: 0, posted: [] as unknown[], disconnected: 0 };
  let onMessage: ((msg: unknown) => void) | undefined;
  let onDisconnect: (() => void) | undefined;

  const port: PortLike = {
    onMessage: { addListener: (cb) => { onMessage = cb; } },
    onDisconnect: { addListener: (cb) => { onDisconnect = cb; } },
    postMessage: (msg) => {
      calls.posted.push(msg);
      // Deliver the simulated outcome on the next microtask, like the browser.
      queueMicrotask(() => {
        if (opts.disconnect) {
          onDisconnect?.();
        } else {
          onMessage?.(opts.reply);
        }
      });
    },
    disconnect: () => { calls.disconnected += 1; },
  };

  const runtime: RuntimeLike = {
    connectNative: (name) => {
      expect(name).toBe(HOST_NAME);
      calls.connected += 1;
      return port;
    },
    lastError: opts.lastError,
  };
  return { runtime, calls };
}

const sampleReq = {
  kind: "secretary-query" as const,
  top_origin: "https://example.com",
  frame_origin: "https://example.com",
  https: true,
};

describe("queryHost", () => {
  it("resolves with the reply and disconnects the port", async () => {
    const reply = { type: "available", request_id: "x", count: 2 };
    const { runtime, calls } = fakeRuntime({ reply });
    const got = await queryHost(runtime, sampleReq);
    expect(got).toEqual(reply);
    expect(calls.connected).toBe(1);
    expect(calls.disconnected).toBe(1);
    // The frame the extension sends to the host is a `query` with the origins.
    expect(calls.posted[0]).toEqual({
      type: "query",
      top_origin: "https://example.com",
      frame_origin: "https://example.com",
      https: true,
    });
  });

  it("rejects with lastError when the host disconnects before replying", async () => {
    const { runtime } = fakeRuntime({
      disconnect: true,
      lastError: { message: "Specified native messaging host not found." },
    });
    await expect(queryHost(runtime, sampleReq)).rejects.toThrow(
      "Specified native messaging host not found.",
    );
  });

  it("rejects with a default message when disconnect has no lastError", async () => {
    const { runtime } = fakeRuntime({ disconnect: true });
    await expect(queryHost(runtime, sampleReq)).rejects.toThrow("native host disconnected");
  });
});
