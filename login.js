// NekoCTI login page. The server sets the session cookie; this page only
// sends the password and shows why a login failed.

const form = document.getElementById("login-form");
const input = document.getElementById("login-password");
const button = document.getElementById("login-button");
const status = document.getElementById("login-status");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  status.textContent = "CHECKING...";
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "X-NekoCTI": "1", "Content-Type": "application/json" },
      body: JSON.stringify({ password: input.value }),
    });
    if (res.ok) {
      location.replace("/");
      return;
    }
    const data = await res.json().catch(() => ({}));
    status.textContent = (res.status === 401 ? "ACCESS DENIED" : data.error || `HTTP ${res.status}`).toUpperCase();
  } catch (err) {
    status.textContent = "SIGNAL LOST - COULD NOT REACH NEKOCTI.";
  }
  input.value = "";
  input.focus();
  button.disabled = false;
});
