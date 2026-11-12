import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiRequest } from "../api";

describe("upstream HTML error handling", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("does not expose a Cloudflare 502 HTML page or upstream hostname", async () => {
    const upstreamHtml =
      "<!DOCTYPE html><html><body><h1>502 Bad Gateway</h1>" +
      "<p>aisoc.rajat.prod.page</p></body></html>";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(upstreamHtml, {
          status: 502,
          statusText: "Bad Gateway",
          headers: { "content-type": "text/html; charset=UTF-8" },
        }),
      ),
    );

    try {
      await apiRequest("/api/v1/cases/example/war-room");
      throw new Error("Expected API request to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      const apiError = error as ApiError;
      expect(apiError.status).toBe(502);
      expect(apiError.body).toBe(
        "The upstream service is temporarily unavailable. Please retry shortly.",
      );
      expect(apiError.body).not.toContain("<html");
      expect(apiError.body).not.toContain("aisoc.rajat.prod.page");
    }
  });

  it("sanitizes HTML even when the proxy mislabels its content type", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("<html><body>internal host</body></html>", {
          status: 503,
          headers: { "content-type": "text/plain" },
        }),
      ),
    );

    await expect(apiRequest("/api/v1/cases/example/war-room")).rejects.toMatchObject({
      status: 503,
      body: "The upstream service is temporarily unavailable. Please retry shortly.",
    });
  });
});
