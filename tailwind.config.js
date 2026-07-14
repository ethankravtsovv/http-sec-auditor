/** Tailwind v3 config — the templates live inside the Python files, so those
 * are the content sources. Rebuild with:
 *   npx tailwindcss@3.4.17 -i tailwind.input.css -o static/tailwind.css --minify
 */
module.exports = {
  content: ["./app.py", "./app_claude.py"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Inter"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
    },
  },
};
