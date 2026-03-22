module.exports = {
  plugins: ["tailwindcss"],
  extends: ["plugin:tailwindcss/recommended"],
  rules: {
    "tailwindcss/no-arbitrary-value": "error",
    "tailwindcss/no-custom-classname": "off"
  }
};