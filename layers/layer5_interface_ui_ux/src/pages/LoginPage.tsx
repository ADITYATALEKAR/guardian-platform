import { useState, type FormEvent } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";

export function LoginPage() {
  const navigate = useNavigate();
  const login = useSessionStore((s) => s.login);
  const busy = useSessionStore((s) => s.busy);
  const error = useSessionStore((s) => s.error);
  const clearError = useSessionStore((s) => s.clearError);

  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const id = identifier.trim();
    if (!id || !password) return;
    try {
      await login(id, password);
      navigate("/dashboard");
    } catch {
      // Error is set in store
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && (
        <div
          style={{
            padding: "8px 12px",
            marginBottom: 16,
            background: "rgba(218, 54, 51, 0.08)",
            border: "1px solid rgba(218, 54, 51, 0.25)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "var(--color-severity-critical)",
          }}
        >
          {error.message}
        </div>
      )}

      <div style={{ marginBottom: 16 }}>
        <label
          style={{
            display: "block",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-label)",
            letterSpacing: "0.2em",
            textTransform: "uppercase",
            color: "var(--muted)",
            marginBottom: 6,
          }}
        >
          User ID
        </label>
        <input
          type="text"
          value={identifier}
          onChange={(e) => {
            setIdentifier(e.target.value);
            if (error) clearError();
          }}
          autoFocus
          autoComplete="username"
          style={{
            width: "100%",
            height: "var(--control-height-default)",
            background: "var(--black)",
            border: "1px solid var(--dim)",
            borderRadius: 2,
            padding: "0 12px",
            color: "var(--white)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-body)",
            outline: "none",
          }}
        />
      </div>

      <div style={{ marginBottom: 24 }}>
        <label
          style={{
            display: "block",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-label)",
            letterSpacing: "0.2em",
            textTransform: "uppercase",
            color: "var(--muted)",
            marginBottom: 6,
          }}
        >
          Password
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            if (error) clearError();
          }}
          autoComplete="current-password"
          style={{
            width: "100%",
            height: "var(--control-height-default)",
            background: "var(--black)",
            border: "1px solid var(--dim)",
            borderRadius: 2,
            padding: "0 12px",
            color: "var(--white)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-body)",
            outline: "none",
          }}
        />
      </div>

      <button
        type="submit"
        className="btn btn-primary"
        disabled={busy || !identifier.trim() || !password}
        style={{ width: "100%", marginBottom: 12 }}
      >
        {busy ? "Signing in..." : "Sign In"}
      </button>

      <div style={{ textAlign: "center" }}>
        <Link
          to="/forgot-password"
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "var(--muted)",
            textDecoration: "underline",
            textUnderlineOffset: 2,
          }}
        >
          Forgot Password?
        </Link>
      </div>
    </form>
  );
}
