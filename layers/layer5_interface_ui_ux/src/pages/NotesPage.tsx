import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSessionStore } from "../stores/useSessionStore";
import { useNotesStore, type Note } from "../stores/useNotesStore";
import { formatTimestamp } from "../lib/formatters";
import { endpointDetailPath } from "../lib/routes";

export function NotesPage() {
  const navigate = useNavigate();
  const session = useSessionStore((s) => s.session);
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const notes = useNotesStore((s) => s.notes);
  const addNote = useNotesStore((s) => s.addNote);
  const deleteNote = useNotesStore((s) => s.deleteNote);
  const [text, setText] = useState("");

  const sortedNotes = useMemo(
    () => [...notes].sort((left, right) => right.created_at_ms - left.created_at_ms),
    [notes],
  );

  function handleAddNote() {
    const trimmed = text.trim();
    if (!trimmed) return;
    addNote({
      text: trimmed,
      object_type: "workspace",
      object_id: tenantId || "workspace",
      created_by: session?.operator_id ?? "unknown",
    });
    setText("");
  }

  return (
    <div className="g-scroll-page">
      <div className="g-scroll-page__body g-scroll-page__body--stack">
        <div className="g-section-label">Notes</div>

        <div style={panelStyle}>
          <div style={introStyle}>
            All saved notes are listed here, including notes attached to individual endpoints. New notes created here
            are workspace-scoped.
          </div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Add a workspace note"
            rows={4}
            style={textareaStyle}
          />
          <div style={toolbarStyle}>
            <span style={metaStyle}>Total notes: {sortedNotes.length}</span>
            <button
              className="btn btn-small btn-primary"
              type="button"
              onClick={handleAddNote}
              disabled={!text.trim()}
            >
              Add Workspace Note
            </button>
          </div>
        </div>

        {sortedNotes.length === 0 ? (
          <div className="g-empty">No notes have been added yet.</div>
        ) : (
          <div style={listStyle}>
            {sortedNotes.map((note) => (
              <div key={note.id} style={cardStyle}>
                <div style={cardHeaderStyle}>
                  <div style={{ flex: 1 }}>
                    <div style={cardTextStyle}>{note.text}</div>
                    <div style={metaStyle}>
                      {scopeLabel(note.object_type, note.object_id)} | {note.created_by} | {formatTimestamp(note.created_at_ms)}
                    </div>
                  </div>
                  <button
                    className="btn btn-small btn-neutral"
                    type="button"
                    onClick={() => deleteNote(note.id)}
                  >
                    Delete
                  </button>
                </div>

                {note.object_type === "endpoint" && (
                  <div style={toolbarStyle}>
                    <span style={metaStyle}>Endpoint-linked note</span>
                    <button
                      className="btn btn-small btn-neutral"
                      type="button"
                      onClick={() => navigate(endpointDetailPath(note.object_id))}
                    >
                      Open Endpoint
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function scopeLabel(objectType: Note["object_type"], objectId: string): string {
  switch (objectType) {
    case "endpoint":
      return `Endpoint | ${objectId}`;
    case "finding":
      return `Finding | ${objectId}`;
    case "alert":
      return `Alert | ${objectId}`;
    case "cycle":
      return `Cycle | ${objectId}`;
    case "simulation":
      return `Simulation | ${objectId}`;
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
  whiteSpace: "pre-wrap" as const,
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

const textareaStyle = {
  width: "100%",
  padding: "8px 10px",
  background: "var(--black)",
  border: "1px solid var(--border)",
  color: "var(--white)",
  fontFamily: "var(--font-mono)",
  fontSize: "var(--font-size-caption)",
  resize: "vertical" as const,
  minHeight: 88,
};
