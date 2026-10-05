import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch, ApiError, getCsrfToken } from "./client";

function mockResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: new Headers({ "X-CSRF-Token": "tok-from-response" }),
    json: async () => body
  } as unknown as Response;
}

describe("apiFetch", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns the JSON payload for a GET and captures the CSRF token", async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(200, { operator: { username: "a" } }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await apiFetch<{ operator: { username: string } }>("/api/v1/sessions");

    expect(result).toEqual({ operator: { username: "a" } });
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/sessions", expect.objectContaining({ method: "GET" }));
    expect(getCsrfToken()).toBe("tok-from-response");
  });

  it("sends JSON and echoes the captured CSRF token on mutations", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(mockResponse(200, { operator: { username: "a" } }))
      .mockResolvedValueOnce(mockResponse(204, null));
    vi.stubGlobal("fetch", fetchMock);

    await apiFetch("/api/v1/sessions");
    const result = await apiFetch<void>("/api/v1/sessions", { method: "DELETE" });

    expect(result).toBeUndefined();
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toBe("/api/v1/sessions");
    expect(init).toEqual(
      expect.objectContaining({
        method: "DELETE",
        headers: expect.objectContaining({ "X-CSRF-Token": "tok-from-response" })
      })
    );
  });

  it("serializes the request body as JSON", async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(201, { operator: { username: "a" } }));
    vi.stubGlobal("fetch", fetchMock);

    await apiFetch("/api/v1/sessions", { method: "POST", body: { username: "a", password: "b" } });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init).toEqual(
      expect.objectContaining({
        body: JSON.stringify({ username: "a", password: "b" }),
        headers: expect.objectContaining({ "Content-Type": "application/json" })
      })
    );
  });

  it("throws ApiError with the server error code", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        mockResponse(404, { error: { code: "not_found", message: "Resource not found" } })
      )
    );

    await expect(apiFetch("/api/v1/issues/999")).rejects.toMatchObject({
      name: "ApiError",
      status: 404,
      code: "not_found",
      message: "Resource not found"
    });
    await expect(apiFetch("/api/v1/issues/999")).rejects.toBeInstanceOf(ApiError);
  });
});
