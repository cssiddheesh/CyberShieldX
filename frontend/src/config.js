const API_BASE_URL = "https://cybershieldx.pages.dev";

export function apiUrl(path) {
  const baseUrl = ["localhost", "127.0.0.1"].includes(window.location.hostname)
    ? window.location.origin
    : API_BASE_URL;

  return `${baseUrl}/api${path}`;
}
