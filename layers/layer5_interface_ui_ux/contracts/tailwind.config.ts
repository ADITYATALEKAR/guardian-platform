/**
 * =========================================================
 * AVYAKTA LAYER 5 — TAILWIND CONTRACT
 * ---------------------------------------------------------
 * This configuration enforces the Layer 5 visual contract.
 * No arbitrary values allowed outside token system.
 *
 * Any inline px values must be removed in code review.
 * =========================================================
 */

/**
 * AVYAKTA LAYER 5 — TAILWIND CONTRACT
 * Palantir-grade enforcement config.
 */

const config = {
  theme: {
    fontFamily: {
      sans: [
        "Inter",
        "-apple-system",
        "BlinkMacSystemFont",
        "Segoe UI",
        "Roboto",
        "sans-serif",
      ],
    },

    fontSize: {
      h1: ["20px", "1.3"],
      h2: ["16px", "1.3"],
      h3: ["14px", "1.3"],
      body: ["14px", "1.5"],
      secondary: ["13px", "1.5"],
      caption: ["12px", "1.4"],
      micro: ["11px", "1.4"],
    },

    spacing: {
      xs: "4px",
      sm: "8px",
      md: "16px",
      lg: "24px",
      xl: "32px",
    },

    colors: {
      appBg: "#0f1419",
      headerBg: "#141a20",
      panelBg: "#1c2228",
      panelMuted: "#20272e",
      border: "#2a333c",

      textPrimary: "#ffffff",
      textSecondary: "#b6c2cf",
      textMuted: "#8a99a8",

      primary: "#2b95d6",
      success: "#15b371",
      warning: "#f29d49",
      danger: "#f55656",
      neutral: "#5c7080",
    },

    borderRadius: {
      sm: "3px",
    },

    height: {
      control: "30px",
      controlSm: "24px",
      controlLg: "40px",
    },
  },
  corePlugins: {
    container: false,
  },
};

export default config;