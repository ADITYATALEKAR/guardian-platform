import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { useNotesStore, type Task, type TaskPriority, type TaskStatus } from "../stores/useNotesStore";
import { formatTimestamp, severityColor } from "../lib/formatters";
import { endpointDetailPath } from "../lib/routes";

const TASK_STATUS_LABELS: Record<TaskStatus, string> = {
  open: "Open",
  in_progress: "In Progress",
  done: "Done",
};

const TASK_PRIORITY_OPTIONS: TaskPriority[] = ["critical", "high", "medium", "low"];

export function TasksPage() {
  const navigate = useNavigate();
  const session = useSessionStore((s) => s.session);
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const tasks = useNotesStore((s) => s.tasks);
  const addTask = useNotesStore((s) => s.addTask);
  const updateTaskStatus = useNotesStore((s) => s.updateTaskStatus);
  const deleteTask = useNotesStore((s) => s.deleteTask);
  const [title, setTitle] = useState("");
  const [priority, setPriority] = useState<TaskPriority>("medium");

  const sortedTasks = useMemo(() => {
    const order: Record<TaskStatus, number> = { open: 0, in_progress: 1, done: 2 };
    return [...tasks].sort((left, right) => {
      const statusDiff = order[left.status] - order[right.status];
      if (statusDiff !== 0) {
        return statusDiff;
      }
      return right.created_at_ms - left.created_at_ms;
    });
  }, [tasks]);

  const openCount = useMemo(
    () => tasks.filter((task) => task.status !== "done").length,
    [tasks],
  );

  function handleAddTask() {
    const trimmed = title.trim();
    if (!trimmed) return;
    addTask({
      title: trimmed,
      description: "",
      status: "open",
      priority,
      due_date: "",
      assigned_to: "",
      object_type: "workspace",
      object_id: tenantId || "workspace",
      created_by: session?.operator_id ?? "unknown",
    });
    setTitle("");
    setPriority("medium");
  }

  function cycleStatus(task: Task) {
    const order: TaskStatus[] = ["open", "in_progress", "done"];
    const currentIndex = order.indexOf(task.status);
    updateTaskStatus(task.id, order[(currentIndex + 1) % order.length]);
  }

  return (
    <div className="g-scroll-page">
      <div className="g-scroll-page__body g-scroll-page__body--stack">
        <div className="g-section-label">Tasks</div>

        <div style={panelStyle}>
          <div style={introStyle}>
            This view aggregates all saved tasks. Tasks created here are workspace-scoped, while endpoint tasks remain
            linked back to their original endpoint.
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 140px auto", gap: 12, alignItems: "end" }}>
            <div>
              <label style={labelStyle}>Task Title</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Add a workspace task"
                style={inputStyle}
              />
            </div>
            <div>
              <label style={labelStyle}>Priority</label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as TaskPriority)}
                style={inputStyle}
              >
                {TASK_PRIORITY_OPTIONS.map((option) => (
                  <option key={option} value={option}>
                    {option.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
            <button
              className="btn btn-small btn-primary"
              type="button"
              onClick={handleAddTask}
              disabled={!title.trim()}
              style={{ alignSelf: "end" }}
            >
              Add Workspace Task
            </button>
          </div>
          <div style={metaStyle}>
            Total tasks: {sortedTasks.length} | Open or in progress: {openCount}
          </div>
        </div>

        {sortedTasks.length === 0 ? (
          <div className="g-empty">No tasks have been added yet.</div>
        ) : (
          <div style={listStyle}>
            {sortedTasks.map((task) => (
              <div key={task.id} style={cardStyle}>
                <div style={cardHeaderStyle}>
                  <button
                    type="button"
                    onClick={() => cycleStatus(task)}
                    title={TASK_STATUS_LABELS[task.status]}
                    style={{
                      width: 16,
                      height: 16,
                      marginTop: 2,
                      border: "1px solid var(--border)",
                      background: task.status === "done" ? "var(--color-severity-low)" : "transparent",
                      cursor: "pointer",
                      flexShrink: 0,
                    }}
                  />
                  <div style={{ flex: 1 }}>
                    <div
                      style={{
                        ...cardTextStyle,
                        color: task.status === "done" ? "var(--muted)" : "var(--white)",
                        textDecoration: task.status === "done" ? "line-through" : "none",
                      }}
                    >
                      {task.title}
                    </div>
                    <div style={metaStyle}>
                      {scopeLabel(task.object_type, task.object_id)} | {task.created_by} | {formatTimestamp(task.created_at_ms)}
                    </div>
                  </div>
                  <button
                    className="btn btn-small btn-neutral"
                    type="button"
                    onClick={() => deleteTask(task.id)}
                  >
                    Delete
                  </button>
                </div>

                <div style={{ ...toolbarStyle, justifyContent: "flex-start" }}>
                  <span style={{ ...pillStyle, color: severityColor(task.priority) }}>
                    {task.priority}
                  </span>
                  <span style={pillStyle}>{TASK_STATUS_LABELS[task.status]}</span>
                  {task.object_type === "endpoint" && (
                    <button
                      className="btn btn-small btn-neutral"
                      type="button"
                      onClick={() => navigate(endpointDetailPath(task.object_id))}
                    >
                      Open Endpoint
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function scopeLabel(objectType: Task["object_type"], objectId: string): string {
  switch (objectType) {
    case "endpoint":
      return `Endpoint | ${objectId}`;
    case "finding":
      return `Finding | ${objectId}`;
    case "workspace":
      return "Workspace";
    default:
      return objectId ? `Linked | ${objectId}` : "Unscoped";
  }
}

const panelStyle = {
  padding: "12px",
  background: "var(--panel)",
  border: "1px solid var(--border)",
  display: "flex",
  flexDirection: "column" as const,
  gap: 12,
};

const listStyle = {
  display: "flex",
  flexDirection: "column" as const,
  gap: 8,
};

const cardStyle = {
  padding: "12px",
  background: "var(--panel)",
  border: "1px solid var(--border)",
  display: "flex",
  flexDirection: "column" as const,
  gap: 10,
};

const cardHeaderStyle = {
  display: "flex",
  alignItems: "flex-start",
  gap: 12,
};

const toolbarStyle = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 12,
  flexWrap: "wrap" as const,
};

const cardTextStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-caption)",
  color: "var(--white)",
  wordBreak: "break-word" as const,
};

const introStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-caption)",
  color: "var(--muted)",
  lineHeight: 1.6,
};

const metaStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-label)",
  color: "var(--muted)",
  letterSpacing: "0.08em",
  textTransform: "uppercase" as const,
};

const labelStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-label)",
  color: "var(--muted)",
  textTransform: "uppercase" as const,
  letterSpacing: "0.1em",
  display: "block",
  marginBottom: 4,
};

const inputStyle = {
  width: "100%",
  padding: "6px 8px",
  background: "var(--black)",
  border: "1px solid var(--border)",
  color: "var(--white)",
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-caption)",
};

const pillStyle = {
  border: "1px solid var(--border)",
  padding: "4px 8px",
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-label)",
  color: "var(--ghost)",
  textTransform: "uppercase" as const,
  letterSpacing: "0.08em",
};
