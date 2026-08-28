/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#07090d",
          900: "#0b0e14",
          850: "#0f131b",
          800: "#131823",
          700: "#1b2230",
          600: "#273042",
        },
        accent: {
          DEFAULT: "#38bdf8",
          dim: "#0ea5e9",
        },
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        low: "#22c55e",
        info: "#64748b",
        healthy: "#22c55e",
        contained: "#38bdf8",
        blocked: "#ef4444",
        investigating: "#eab308",
        remediated: "#22c55e",
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(56, 189, 248, 0.12)",
        panel: "0 4px 24px rgba(0,0,0,0.45)",
      },
    },
  },
  plugins: [],
};
