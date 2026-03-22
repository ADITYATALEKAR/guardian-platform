import { useMemo, useState } from "react";
import { useNotesStore, type Task, type TaskStatus, type TaskPriority } from "../stores/useNotesStore";
import { useSessionStore } from "../stores/useSessionStore";
import { severityColor } from "../lib/formatters";

interface TasksSectionProps {
  objectType: Task["object_type"];
  objectId: string;
}

const STATUS_LABELS: Record<TaskStatus, string> = { open: "Open", in_progress: "In Progress", done: "Done" };
const PRIORITY_OPTIONS: TaskPriority[] = ["critical", "high", "medium", "low"];

export function TasksSection({ objectType, objectId }: TasksSectionProps) {
  const session = useSessionStore((s) => s.session);
  const allTasks = useNotesStore((s) => s.tasks);
  const addTask = useNotesStore((s) => s.addTask);
  const updateStatus = useNotesStore((s) => s.updateTaskStatus);
  const deleteTask = useNotesStore((s) => s.deleteTask);

  const [showForm, setShowForm] = useState(false);
  const [title, setTitle] = useState("");
  const [priority, setPriority] = useState<TaskPriority>("medium");
  const tasks = useMemo(
    () => allTasks.filter((task) => task.object_type === objectType && task.object_id === objectId),
    [allTasks, objectType, objectId],
  );

  function handleAdd() {
    const trimmed = title.trim();
    if (!trimmed) return;
    addTask({
      title: trimmed,
      description: "",
      status: "open",
      priority,
      due_date: "",
      assigned_to: "",
      object_type: objectType || "",
      object_id: objectId,
      created_by: session?.operator_id ?? "unknown",
    });
    setTitle("");
    setShowForm(false);
  }

  function cycleStatus(task: Task) {
    const order: TaskStatus[] = ["open", "in_progress", "done"];
    const idx = order.indexOf(task.status);
    updateStatus(task.id, order[(idx + 1) % order.length]);
  }

  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em" }}>
          Tasks ({tasks.length})
        </span>
        <button className="btn btn-small btn-neutral" onClick={() => setShowForm(!showForm)} style={{ fontSize: 11 }}>
          {showForm ? "Cancel" : "+ Task"}
        </button>
      </div>

      {showForm && (
        <div style={{ display: "flex", gap: 6, marginBottom: 8 }}>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAdd()}
            placeholder="Task title..."
            style={{
              flex: 1, padding: "6px 8px",
              background: "var(--black)", border: "1px solid var(--border)",
              color: "var(--white)", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
            }}
          />
          <select
            value={priority}
            onChange={(e) => setPriority(e.target.value as TaskPriority)}
            style={{
              padding: "4px 8px", background: "var(--black)", border: "1px solid var(--border)",
              color: "var(--white)", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
            }}
          >
            {PRIORITY_OPTIONS.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <button className="btn btn-small btn-primary" onClick={handleAdd} disabled={!title.trim()}>
            Add
          </button>
        </div>
      )}

      {tasks.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {tasks.map((task) => (
            <div key={task.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 8px", background: "var(--panel)", border: "1px solid var(--border)" }}>
              <button
                onClick={() => cycleStatus(task)}
                style={{
                  width: 16, height: 16, border: "1px solid var(--border)",
                  background: task.status === "done" ? "var(--color-severity-low)" : "transparent",
                  cursor: "pointer", flexShrink: 0,
                }}
                title={STATUS_LABELS[task.status]}
              />
              <span style={{
                fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
                color: task.status === "done" ? "var(--muted)" : "var(--ghost)",
                textDecoration: task.status === "done" ? "line-through" : "none",
                flex: 1,
              }}>
                {task.title}
              </span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: severityColor(task.priority), textTransform: "uppercase" }}>
                {task.priority}
              </span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase" }}>
                {STATUS_LABELS[task.status]}
              </span>
              <button
                onClick={() => deleteTask(task.id)}
                style={{ background: "none", border: "none", color: "var(--muted)", cursor: "pointer", fontSize: 12 }}
              >
                x
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
