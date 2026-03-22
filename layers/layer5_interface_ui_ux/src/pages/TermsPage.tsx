import { Link } from "react-router-dom";

export function TermsPage() {
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
        Terms of Use
      </h1>
      <p style={{ fontSize: 12, color: "var(--muted)", marginBottom: 32 }}>
        Last updated: March 2026
      </p>

      <Section title="1. Acceptance of Terms">
        By accessing or using the Guardian External Attack Surface Management
        platform ("Service"), you agree to be bound by these Terms of Use. If
        you do not agree to these terms, do not use the Service.
      </Section>

      <Section title="2. Description of Service">
        Guardian is a security posture intelligence platform that performs
        external discovery and analysis of cryptographic configurations across
        publicly observable endpoints. The Service operates entirely externally
        and does not require internal network access.
      </Section>

      <Section title="3. Authorized Use">
        You may use the Service only for lawful purposes and in accordance with
        these Terms. You agree not to use the Service to: (a) scan or analyze
        domains or infrastructure you do not own or have explicit authorization
        to assess; (b) attempt to gain unauthorized access to any system; (c)
        violate any applicable law or regulation; (d) interfere with or disrupt
        the Service or servers.
      </Section>

      <Section title="4. User Accounts">
        You are responsible for maintaining the confidentiality of your account
        credentials. You agree to notify us immediately of any unauthorized use
        of your account. We reserve the right to suspend or terminate accounts
        that violate these Terms.
      </Section>

      <Section title="5. Data Collection and Processing">
        The Service collects and processes only publicly observable data
        including TLS certificates, DNS records, HTTP headers, and related
        metadata. No private or internal data is accessed. Scan results and
        analytics are stored securely and isolated per tenant.
      </Section>

      <Section title="6. Intellectual Property">
        All content, features, and functionality of the Service are owned by
        Fundamental Labs and are protected by international copyright,
        trademark, and other intellectual property laws.
      </Section>

      <Section title="7. Disclaimer of Warranties">
        The Service is provided "as is" and "as available" without warranties
        of any kind, either express or implied. We do not warrant that the
        Service will be uninterrupted, error-free, or that results will be
        accurate or complete.
      </Section>

      <Section title="8. Limitation of Liability">
        To the fullest extent permitted by law, Fundamental Labs shall not be
        liable for any indirect, incidental, special, consequential, or
        punitive damages arising out of or relating to your use of the Service.
      </Section>

      <Section title="9. Modifications">
        We reserve the right to modify these Terms at any time. Continued use
        of the Service after changes constitutes acceptance of the modified
        Terms.
      </Section>

      <Section title="10. Governing Law">
        These Terms shall be governed by and construed in accordance with the
        laws of India, without regard to conflict of law principles.
      </Section>

      <Section title="11. Contact">
        For questions about these Terms, contact us at
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
