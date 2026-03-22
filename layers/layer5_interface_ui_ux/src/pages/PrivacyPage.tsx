import { Link } from "react-router-dom";

export function PrivacyPage() {
  return (
    <div
      style={{
        maxWidth: 720,
        margin: "0 auto",
        padding: "48px 24px",
        fontFamily: "var(--font-primary)",
        color: "var(--white)",
        lineHeight: 1.7,
      }}
    >
      <Link
        to="/login"
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          color: "var(--muted)",
          textDecoration: "underline",
          textUnderlineOffset: 2,
        }}
      >
        &larr; Back
      </Link>

      <h1
        style={{
          fontFamily: "var(--font-display)",
          fontSize: 28,
          fontWeight: 700,
          color: "var(--pure)",
          margin: "24px 0 8px",
        }}
      >
        Privacy Policy
      </h1>
      <p style={{ fontSize: 12, color: "var(--muted)", marginBottom: 32 }}>
        Last updated: March 2026
      </p>

      <Section title="1. Information We Collect">
        We collect the following information: (a) account information you
        provide during registration, including email address and institution
        name; (b) publicly observable data from external endpoints including
        TLS certificates, DNS records, HTTP headers, and cryptographic
        configurations; (c) usage data such as login timestamps and session
        metadata.
      </Section>

      <Section title="2. How We Use Information">
        We use collected information to: (a) provide and maintain the Service;
        (b) analyze external security posture of your registered endpoints; (c)
        generate security findings, compliance evidence, and risk assessments;
        (d) improve and optimize the Service.
      </Section>

      <Section title="3. Data Storage and Security">
        All data is stored with tenant isolation ensuring strict separation
        between organizations. Passwords are hashed using PBKDF2-SHA256 with
        200,000 iterations and unique salts. Session tokens are securely
        generated and time-limited. We do not store plaintext passwords.
      </Section>

      <Section title="4. Data We Do Not Collect">
        Guardian operates entirely externally. We do not: (a) access internal
        networks or systems; (b) install agents or software on your
        infrastructure; (c) collect private keys, internal configurations, or
        non-public data; (d) perform active exploitation or penetration
        testing.
      </Section>

      <Section title="5. Data Sharing">
        We do not sell, trade, or rent your personal information to third
        parties. We may share information only: (a) with your consent; (b) to
        comply with legal obligations; (c) to protect our rights or the safety
        of users.
      </Section>

      <Section title="6. Data Retention">
        Account data is retained for the duration of your active account. Scan
        results and cycle data are retained to provide historical trend
        analysis. You may request deletion of your account and associated data
        by contacting us.
      </Section>

      <Section title="7. Your Rights">
        You have the right to: (a) access your personal data; (b) correct
        inaccurate data; (c) request deletion of your data; (d) export your
        scan results and findings. Contact us to exercise these rights.
      </Section>

      <Section title="8. Cookies and Tracking">
        The Service uses local storage for session management. We do not use
        third-party tracking cookies or analytics services.
      </Section>

      <Section title="9. Changes to This Policy">
        We may update this Privacy Policy from time to time. We will notify
        users of material changes through the Service interface.
      </Section>

      <Section title="10. Contact">
        For privacy-related inquiries, contact us at
        aditya.a.talekar@gmail.com.
      </Section>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom: 28 }}>
      <h2
        style={{
          fontFamily: "var(--font-primary)",
          fontSize: 15,
          fontWeight: 600,
          color: "var(--pure)",
          marginBottom: 8,
        }}
      >
        {title}
      </h2>
      <p style={{ fontSize: 13, color: "rgba(224,224,224,0.72)", margin: 0 }}>
        {children}
      </p>
    </div>
  );
}
