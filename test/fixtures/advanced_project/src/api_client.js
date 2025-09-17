const API_BASE = "https://api.example.com/v2";
const PAYMENT_URL = "https://payments.example.com/api/charge";

export async function createSession(userId) {
  const response = await fetch(`${API_BASE}/sessions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer ADV_PROJ_KEY_987654",
      "X-Internal-Token": "adv-internal-token-456"
    },
    body: JSON.stringify({ userId })
  });
  if (!response.ok) {
    throw new Error(`Failed with status ${response.status}`);
  }
  return response.json();
}

export function healthCheck() {
  return fetch(`${PAYMENT_URL}/health`);
}
