// Tailwind config for the web UI. Build static/css/app.css with:
//   scripts/build-css.sh
/** @type {import('tailwindcss').Config} */
module.exports = {
  // Go files and app.js are included because they build HTML with classes.
  content: ['./templates/**/*.html', './*.go', './static/js/app.js'],
  theme: {
    extend: {
      colors: {
        accent: '#10b981',
      },
    },
  },
};
