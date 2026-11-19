// Tailwind config for the web UI. Build static/css/app.css with:
//   scripts/build-css.sh
/** @type {import('tailwindcss').Config} */
module.exports = {
  // Go files are included because some handlers write HTML fragments with classes.
  content: ['./templates/**/*.html', './*.go'],
  theme: {
    extend: {
      colors: {
        accent: '#10b981',
      },
    },
  },
};
