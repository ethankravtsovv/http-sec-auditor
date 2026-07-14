// Copy-to-clipboard for the remediation/example code blocks. Lives here
// instead of inline onclick handlers so the CSP can stay script-src 'self'.
document.addEventListener("click", (event) => {
  const trigger = event.target.closest("[data-copy]");
  if (!trigger) return;
  const block = trigger.closest("[data-copy-block]");
  const code = block && block.querySelector("code");
  if (code) navigator.clipboard.writeText(code.textContent);
});
