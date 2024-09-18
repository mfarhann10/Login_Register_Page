// public/tailwind.config.js
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './public/**/*.{html,js,css}',
    './views/**/*.ejs',  // Termasuk semua file EJS di dalam folder views
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
