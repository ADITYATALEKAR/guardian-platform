import { Navigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const session = useSessionStore((s) => s.session);

  if (!session) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}
