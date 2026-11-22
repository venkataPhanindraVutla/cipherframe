import "../src/index";

// Optional: #<base64url of the session JSON>, for trying a session by hand. The hash never goes to a server.
const hash = location.hash.slice(1);
if (hash) {
  const json = atob(hash.replaceAll("-", "+").replaceAll("_", "/"));
  document.querySelector("cipherframe-player")?.load(JSON.parse(json));
}
