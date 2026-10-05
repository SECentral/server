import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { Login } from "./Login";

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: new Headers({ "X-CSRF-Token": "tok" }),
    json: async () => body
  } as unknown as Response;
}

function renderLogin() {
  const queryClient = new QueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/login"]}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <div>authenticated app</div>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("Login", () => {
  it("posts credentials to /api/v1/sessions and enters the app on success", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(201, { operator: { username: "test-admin" } }))
      .mockResolvedValue(jsonResponse(200, { operator: { username: "test-admin" } }));
    vi.stubGlobal("fetch", fetchMock);

    const user = userEvent.setup();
    renderLogin();

    await user.type(screen.getByLabelText(/username/i), "test-admin");
    await user.type(screen.getByLabelText(/password/i), "test-password");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(screen.getByText("authenticated app")).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/sessions",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ username: "test-admin", password: "test-password" })
      })
    );
  });

  it("shows the server error for invalid credentials", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(401, { error: { code: "unauthorized", message: "Invalid credentials" } })
      )
    );

    const user = userEvent.setup();
    renderLogin();

    await user.type(screen.getByLabelText(/username/i), "test-admin");
    await user.type(screen.getByLabelText(/password/i), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("Invalid credentials")).toBeInTheDocument();
  });
});
