import { useNavigate } from "react-router-dom";
import { EmptyState } from "../components/feedback/EmptyState";

export function NotFoundPage() {
  const navigate = useNavigate();
  return (
    <EmptyState
      message="Page not found. The route you requested does not exist."
      action="Go to Dashboard"
      onAction={() => navigate("/dashboard")}
    />
  );
}
