import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { dataSource, Layer5ApiError } from "../lib/api";

export function ForgotPasswordPage() {
  const [identifier, setIdentifier] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [step, setStep] = useState<"identify" | "reset">("identify");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleIdentify = (e: FormEvent) => {
    e.preventDefault();
    if (!identifier.trim()) return;
    setError(null);
    setStep("reset");
  };

  const handleReset = async (e: FormEvent) => {
    e.preventDefault();
    if (!newPassword || !confirmPassword) return;
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (newPassword.length < 12) {
      setError("Password must be at least 12 characters.");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await dataSource.resetPassword(identifier.trim(), newPassword);
      setSuccess(true);
    } catch (err) {
      const msg =
        err instanceof Layer5ApiError
          ? err.message
          : "Reset failed. Check your User ID / Email.";
      setError(msg);
    } finally {
      setBusy(false);
    }
  };

  const labelStyle: React.CSSProperties = {
    display: "block",
    fontFamily: "var(--font-mono)",
    fontSize: "var(--font-size-label)",
    letterSpacing: "0.2em",
    textTransform: "uppercase",
    color: "var(--muted)",
    marginBottom: 6,
  };

  const inputStyle: React.CSSProperties = {
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
  };

  if (success) {
    return (
      <div>
        <div
          style={{
            padding: "12px 16px",
            marginBottom: 20,
            background: "rgba(34, 197, 94, 0.08)",
            border: "1px solid rgba(34, 197, 94, 0.25)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "#22c55e",
          }}
        >
          Password reset successfully.
        </div>
        <Link
          to="/login"
          className="btn btn-primary"
          style={{
            width: "100%",
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            textDecoration: "none",
          }}
        >
          Back to Sign In
        </Link>
      </div>
    );
  }

  if (step === "identify") {
    return (
      <form onSubmit={handleIdentify}>
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
            {error}
          </div>
        )}

        <div style={{ marginBottom: 16 }}>
          <label style={labelStyle}>User ID or Email</label>
          <input
            type="text"
            value={identifier}
            onChange={(e) => {
              setIdentifier(e.target.value);
              setError(null);
            }}
            autoFocus
            style={inputStyle}
          />
        </div>

        <button
          type="submit"
          className="btn btn-primary"
          disabled={!identifier.trim()}
          style={{ width: "100%", marginBottom: 12 }}
        >
          Continue
        </button>

        <div style={{ textAlign: "center" }}>
          <Link
            to="/login"
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "var(--font-size-caption)",
              color: "var(--muted)",
              textDecoration: "underline",
              textUnderlineOffset: 2,
            }}
          >
            Back to Sign In
          </Link>
        </div>
      </form>
    );
  }

  return (
    <form onSubmit={handleReset}>
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
          {error}
        </div>
      )}

      <div style={{ marginBottom: 16 }}>
        <label style={labelStyle}>New Password</label>
        <input
          type="password"
          value={newPassword}
          onChange={(e) => {
            setNewPassword(e.target.value);
            setError(null);
          }}
          autoFocus
          autoComplete="new-password"
          style={inputStyle}
        />
      </div>

      <div style={{ marginBottom: 24 }}>
        <label style={labelStyle}>Confirm Password</label>
        <input
          type="password"
          value={confirmPassword}
          onChange={(e) => {
            setConfirmPassword(e.target.value);
            setError(null);
          }}
          autoComplete="new-password"
          style={inputStyle}
        />
      </div>

      <button
        type="submit"
        className="btn btn-primary"
        disabled={busy || !newPassword || !confirmPassword}
        style={{ width: "100%", marginBottom: 12 }}
      >
        {busy ? "Resetting..." : "Reset Password"}
      </button>

      <div style={{ textAlign: "center" }}>
        <Link
          to="/login"
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "var(--muted)",
            textDecoration: "underline",
            textUnderlineOffset: 2,
          }}
        >
          Back to Sign In
        </Link>
      </div>
    </form>
  );
}
