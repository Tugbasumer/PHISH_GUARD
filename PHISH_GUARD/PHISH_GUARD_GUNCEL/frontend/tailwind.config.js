/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            fontFamily: {
                sans: ['Inter', 'sans-serif'],
                mono: ['"JetBrains Mono"', 'monospace'],
            },
            colors: {
                cyber: {
                    900: '#0a0a0a', // Almost black
                    800: '#111111', // Dark grey
                    700: '#1a1a1a', // Panel grey
                    primary: '#00ff9d', // Neon Green
                    secondary: '#00ccff', // Cyber Blue
                    accent: '#ff00ff', // Neon Pink
                }
            },
            boxShadow: {
                'neon-green': '0 0 10px rgba(0, 255, 157, 0.5), 0 0 20px rgba(0, 255, 157, 0.3)',
                'neon-blue': '0 0 10px rgba(0, 204, 255, 0.5), 0 0 20px rgba(0, 204, 255, 0.3)',
            }
        },
    },
    plugins: [],
}
