/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                'sentry-dark': '#0f172a',
                'sentry-card': '#1e293b',
                'sentry-accent': '#38bdf8',
            }
        },
    },
    plugins: [],
}