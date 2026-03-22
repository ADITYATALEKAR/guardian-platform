from __future__ import annotations

from dataclasses import dataclass

from infrastructure.storage_manager.storage_manager import StorageManager

from .notification_outbox import NotificationOutbox


@dataclass(frozen=True)
class NotificationDispatcher:
    storage_manager: StorageManager
    tenant_id: str

    def dispatch(self, *, max_items: int = 50) -> int:
        cap = max(0, int(max_items))
        outbox = NotificationOutbox(self.storage_manager, self.tenant_id)
        sent_count = 0
        for item in outbox.list_pending():
            if sent_count >= cap:
                break
            event_id = str(item.get("event_id", "")).strip()
            if not event_id:
                raise RuntimeError("corrupt notification outbox")
            outbox.mark_sent(event_id)
            sent_count += 1
        return sent_count
