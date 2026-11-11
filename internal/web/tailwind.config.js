// Tailwind config for the web UI. Generates internal/web/static/css/app.css.
// Regenerate after changing classes in templates or server.go:
//
//   tailwindcss -c internal/web/tailwind.config.js \
//     -i internal/web/tailwind.input.css \
//     -o internal/web/static/css/app.css --minify
//
// Uses the Tailwind v3.4.1 standalone CLI:
// https://github.com/tailwindlabs/tailwindcss/releases/tag/v3.4.1
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './internal/web/templates/**/*.html',
    './internal/web/*.go',
  ],
  theme: {
    extend: {
      colors: {
        accent: '#10b981',
      },
    },
  },
  plugins: [],
}
