import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";

export function RegisterPage() {
  const navigate = useNavigate();
  const register = useSessionStore((s) => s.register);
  const login = useSessionStore((s) => s.login);
  const busy = useSessionStore((s) => s.busy);
  const error = useSessionStore((s) => s.error);
  const clearError = useSessionStore((s) => s.clearError);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [institutionName, setInstitutionName] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimEmail = email.trim();
    if (!trimEmail || !password) return;
    if (password !== confirmPassword) {
      setValidationError("Password and confirm password must match.");
      return;
    }
    setValidationError(null);
    try {
      await register({
        email: trimEmail,
        password,
        institution_name: institutionName.trim() || undefined,
      });
      // Auto-login after registration
      await login(trimEmail, password);
      navigate("/onboarding");
    } catch {
      // Error set in store
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {(validationError || error) && (
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
          {validationError ?? error?.message}
        </div>
      )}

      <InputField label="Email" value={email} onChange={(v) => { setEmail(v); if (error) clearError(); if (validationError) setValidationError(null); }} type="email" autoFocus />
      <InputField label="Password" value={password} onChange={(v) => { setPassword(v); if (error) clearError(); if (validationError) setValidationError(null); }} type="password" />
      <InputField label="Confirm Password" value={confirmPassword} onChange={(v) => { setConfirmPassword(v); if (error) clearError(); if (validationError) setValidationError(null); }} type="password" />
      <InputField label="Institution Name" value={institutionName} onChange={setInstitutionName} placeholder="Optional" />

      <button
        type="submit"
        className="btn btn-primary"
        disabled={busy || !email.trim() || !password || !confirmPassword}
        style={{ width: "100%", marginBottom: 0, marginTop: 8 }}
      >
        {busy ? "Creating account..." : "Create Account"}
      </button>
    </form>
  );
}

function InputField({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  autoFocus,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
  autoFocus?: boolean;
}) {
  return (
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
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoFocus={autoFocus}
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
  );
}
