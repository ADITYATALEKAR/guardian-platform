import { useMemo, useState } from "react";
import { useNotesStore, type Note } from "../stores/useNotesStore";
import { useSessionStore } from "../stores/useSessionStore";
import { formatTimestamp } from "../lib/formatters";

interface NotesSectionProps {
  objectType: Note["object_type"];
  objectId: string;
}

export function NotesSection({ objectType, objectId }: NotesSectionProps) {
  const session = useSessionStore((s) => s.session);
  const allNotes = useNotesStore((s) => s.notes);
  const addNote = useNotesStore((s) => s.addNote);
  const deleteNote = useNotesStore((s) => s.deleteNote);
  const [text, setText] = useState("");
  const notes = useMemo(
    () => allNotes.filter((note) => note.object_type === objectType && note.object_id === objectId),
    [allNotes, objectType, objectId],
  );

  function handleAdd() {
    const trimmed = text.trim();
    if (!trimmed) return;
    addNote({
      text: trimmed,
      object_type: objectType,
      object_id: objectId,
      created_by: session?.operator_id ?? "unknown",
    });
    setText("");
  }

  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.15em", marginBottom: 6 }}>
        Notes ({notes.length})
      </div>

      {/* Add note */}
      <div style={{ display: "flex", gap: 6, marginBottom: 8 }}>
        <input
          type="text"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleAdd()}
          placeholder="Add a note..."
          style={{
            flex: 1, padding: "6px 8px",
            background: "var(--black)", border: "1px solid var(--border)",
            color: "var(--white)", fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)",
          }}
        />
        <button className="btn btn-small btn-primary" onClick={handleAdd} disabled={!text.trim()}>
          Add
        </button>
      </div>

      {/* Notes list */}
      {notes.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {notes.map((note) => (
            <div key={note.id} style={{ display: "flex", gap: 8, padding: "6px 8px", background: "var(--panel)", border: "1px solid var(--border)" }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-caption)", color: "var(--ghost)" }}>
                  {note.text}
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "var(--font-size-label)", color: "var(--muted)", marginTop: 2 }}>
                  {note.created_by} &middot; {formatTimestamp(note.created_at_ms)}
                </div>
              </div>
              <button
                onClick={() => deleteNote(note.id)}
                style={{ background: "none", border: "none", color: "var(--muted)", cursor: "pointer", fontSize: 12, alignSelf: "flex-start" }}
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
