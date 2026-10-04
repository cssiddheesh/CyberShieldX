import { apiUrl } from "./config.js";

export class ApiError extends Error {
  constructor(message, status, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request(path, { method = "GET", body, timeout = 15000, signal } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  signal?.addEventListener("abort", () => controller.abort());
  try {
    const response = await fetch(apiUrl(path), {
      method,
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    let data = null;
    try {
      data = await response.json();
    } catch {
      /* non-JSON response */
    }
    if (!response.ok) {
      const message = data?.error?.message || `The server returned an error (${response.status}).`;
      throw new ApiError(message, response.status, data?.error?.code);
    }
    return data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error.name === "AbortError") {
      if (signal?.aborted) throw error;
      throw new ApiError("The server took too long to respond. Try again.", 0, "timeout");
    }
    throw new ApiError("Can't reach the CyberShield X server. Check that it is still running.", 0, "network");
  } finally {
    clearTimeout(timer);
  }
}

export const api = {
  get: (path, options) => request(path, options),
  delete: (path) => request(path, { method: "DELETE" }),
  put: (path, body) => request(path, { method: "PUT", body }),
  post: (path, body, options) => request(path, { method: "POST", body, ...options }),
  upload: async (path, formData, { timeout = 60000, signal } = {}) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    signal?.addEventListener("abort", () => controller.abort());
    try {
      const response = await fetch(apiUrl(path), { method: "POST", body: formData, signal: controller.signal });
      let data = null;
      try {
        data = await response.json();
      } catch {
        /* non-JSON response */
      }
      if (!response.ok) {
        const message = data?.error?.message || `The server returned an error (${response.status}).`;
        throw new ApiError(message, response.status, data?.error?.code);
      }
      return data;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if (error.name === "AbortError") {
        if (signal?.aborted) throw error;
        throw new ApiError("The server took too long to respond. Try again.", 0, "timeout");
      }
      throw new ApiError("Can't reach the CyberShield X server. Check that it is still running.", 0, "network");
    } finally {
      clearTimeout(timer);
    }
  },
};
