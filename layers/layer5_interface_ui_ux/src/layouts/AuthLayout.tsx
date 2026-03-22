import { Outlet, useLocation, Link } from "react-router-dom";
import { BrandLotus } from "../components/BrandLotus";
import "./auth-layout.css";

const valueRows = [
  {
    label: "The Problem",
    title: "Invisible Risk",
    body: (
      <>
        <strong>Cryptographic failures are silent until they're catastrophic.</strong>{" "}
        Expired certificates, weak ciphers, and quantum-vulnerable keys sit
        undetected across your external infrastructure - found only during
        incidents or formal audits.
      </>
    ),
  },
  {
    label: "Our Answer",
    title: "Continuous External Visibility",
    body: (
      <>
        Guardian runs <strong>deterministic discovery cycles</strong> across every
        endpoint, tenant, and subsidiary - producing live posture findings,
        compliance-mapped evidence, and quantum-readiness scores in one unified
        console.{" "}
        <strong>Entirely external. No agents, no internal access required.</strong>{" "}
        We work only with publicly observable metadata.
      </>
    ),
  },
  {
    label: "The Outcome",
    title: "Audit-Ready, Always",
    body: (
      <>
        Security teams <strong>detect drift before it becomes a breach.</strong>{" "}
        Compliance teams export audit artifacts in minutes, not weeks.
        Leadership gets a defensible posture view - ready for any regulator, any
        time.
      </>
    ),
  },
  {
    label: "The Difference",
    title: "Operational Clarity",
    body: (
      <>
        Simulator workflows validate response options safely, and metadata
        continuity keeps every action traceable to tenant, cycle, and endpoint
        - from detection to governance review.
      </>
    ),
  },
];

export function AuthLayout() {
  const location = useLocation();
  const isLogin = location.pathname !== "/register";
  const layoutClassName = `auth-layout${isLogin ? " auth-layout--login" : " auth-layout--register"}`;

  return (
    <div className={layoutClassName}>
      <div className="auth-layout__stage">
        <section className="auth-layout__story" aria-label="Platform overview">
          <div className="auth-layout__story-brand">
            <BrandLotus
              style={{
                width: 32,
                height: 32,
                color: "var(--pure)",
                ["--brand-lotus-fill" as string]: "var(--black)",
              }}
            />
            <span className="auth-layout__story-brand-word">Guardian</span>
          </div>

          <div className="auth-layout__eyebrow">
            External Attack Surface Management
          </div>

          <h1 className="auth-layout__headline">
            Your cryptographic blind spot ends here.
          </h1>

          <p className="auth-layout__lede">
            Banks and institutions run thousands of endpoints. Most only discover
            cryptographic failures during a breach or a regulator&apos;s visit.
            Guardian changes when you find out - from after the fact, to always.
          </p>

          <div className="auth-layout__value-rows">
            {valueRows.map((row) => (
              <article key={row.label} className="auth-layout__value-row">
                <div className="auth-layout__value-rail">
                  <div className="auth-layout__value-label">{row.label}</div>
                  <div className="auth-layout__value-title">{row.title}</div>
                </div>
                <div className="auth-layout__value-body">
                  <p>{row.body}</p>
                </div>
              </article>
            ))}
          </div>

          <div className="auth-layout__story-footer">
            <div className="auth-layout__footer-links">
              <Link to="/terms">Terms of Use</Link>
              <span className="auth-layout__footer-sep">|</span>
              <Link to="/privacy">Privacy Policy</Link>
              <span className="auth-layout__footer-sep">|</span>
              <a href="#contact" className="auth-layout__contact-link">Contact</a>
            </div>
            <div className="auth-layout__footer-contact" id="contact">
              <div className="auth-layout__contact-name">Aditya Talekar</div>
              <div className="auth-layout__contact-role">Founder, Fundamental Labs</div>
              <div className="auth-layout__contact-detail">aditya.a.talekar@gmail.com</div>
              <div className="auth-layout__contact-detail">+91 96739 04714</div>
            </div>
          </div>
        </section>

        <aside className="auth-layout__access" aria-label="Authentication">
          <div className="auth-layout__access-inner">
            <div className="auth-layout__welcome">Welcome to Guardian</div>

            <nav className="auth-layout__tabs">
              <Link
                to="/login"
                className={`auth-layout__tab${isLogin ? " auth-layout__tab--active" : ""}`}
              >
                Sign In
              </Link>
              <Link
                to="/register"
                className={`auth-layout__tab${!isLogin ? " auth-layout__tab--active" : ""}`}
              >
                Register
              </Link>
            </nav>

            <div className="auth-layout__card">
              <Outlet />
            </div>
          </div>

          <div className="auth-layout__access-footer">
            <div className="auth-layout__footer-legal">
              Use limited to authorized security operations.
            </div>
            <div className="auth-layout__footer-copyright">
              &copy; 2025 Guardian, a product of Fundamental Labs. All rights reserved.
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
