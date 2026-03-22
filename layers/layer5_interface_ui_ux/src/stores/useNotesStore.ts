import { create } from "zustand";

export type NoteObjectType = "endpoint" | "finding" | "alert" | "cycle" | "simulation" | "workspace";
export type TaskObjectType = "endpoint" | "finding" | "workspace" | "";

// ─── Notes ───

export interface Note {
  id: string;
  text: string;
  object_type: NoteObjectType;
  object_id: string;
  created_at_ms: number;
  created_by: string;
}

// ─── Tasks ───

export type TaskStatus = "open" | "in_progress" | "done";
export type TaskPriority = "critical" | "high" | "medium" | "low";

export interface Task {
  id: string;
  title: string;
  description: string;
  status: TaskStatus;
  priority: TaskPriority;
  due_date: string;
  assigned_to: string;
  object_type: TaskObjectType;
  object_id: string;
  created_at_ms: number;
  created_by: string;
}

// ─── Store ───

const NOTES_KEY = "guardian_notes";
const TASKS_KEY = "guardian_tasks";

function loadNotes(): Note[] {
  try {
    const raw = localStorage.getItem(NOTES_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function loadTasks(): Task[] {
  try {
    const raw = localStorage.getItem(TASKS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function persistNotes(notes: Note[]) {
  localStorage.setItem(NOTES_KEY, JSON.stringify(notes));
}

function persistTasks(tasks: Task[]) {
  localStorage.setItem(TASKS_KEY, JSON.stringify(tasks));
}

function makeId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

interface NotesTasksStore {
  notes: Note[];
  tasks: Task[];

  addNote: (params: Pick<Note, "text" | "object_type" | "object_id" | "created_by">) => void;
  deleteNote: (noteId: string) => void;
  getNotesFor: (objectType: string, objectId: string) => Note[];

  addTask: (params: Omit<Task, "id" | "created_at_ms">) => void;
  updateTaskStatus: (taskId: string, status: TaskStatus) => void;
  deleteTask: (taskId: string) => void;
  getTasksFor: (objectType: string, objectId: string) => Task[];
}

export const useNotesStore = create<NotesTasksStore>((set, get) => ({
  notes: loadNotes(),
  tasks: loadTasks(),

  addNote: ({ text, object_type, object_id, created_by }) => {
    const note: Note = {
      id: makeId(),
      text,
      object_type,
      object_id,
      created_at_ms: Date.now(),
      created_by,
    };
    const next = [note, ...get().notes];
    persistNotes(next);
    set({ notes: next });
  },

  deleteNote: (noteId) => {
    const next = get().notes.filter((n) => n.id !== noteId);
    persistNotes(next);
    set({ notes: next });
  },

  getNotesFor: (objectType, objectId) => {
    return get().notes.filter((n) => n.object_type === objectType && n.object_id === objectId);
  },

  addTask: (params) => {
    const task: Task = {
      ...params,
      id: makeId(),
      created_at_ms: Date.now(),
    };
    const next = [task, ...get().tasks];
    persistTasks(next);
    set({ tasks: next });
  },

  updateTaskStatus: (taskId, status) => {
    const next = get().tasks.map((t) => (t.id === taskId ? { ...t, status } : t));
    persistTasks(next);
    set({ tasks: next });
  },

  deleteTask: (taskId) => {
    const next = get().tasks.filter((t) => t.id !== taskId);
    persistTasks(next);
    set({ tasks: next });
  },

  getTasksFor: (objectType, objectId) => {
    return get().tasks.filter((t) => t.object_type === objectType && t.object_id === objectId);
  },
}));
