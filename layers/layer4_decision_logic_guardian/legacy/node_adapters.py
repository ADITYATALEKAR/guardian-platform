class ServiceNode:
    """
    Layer4 public abstraction.
    Does NOT depend on Layer1 implementation.
    """

    def __init__(self, *, node_id: str, kind: str = "service", meta=None):
        self.node_id = node_id
        self.kind = kind
        self.meta = meta or {}

    @classmethod
    def from_layer1(cls, node):
        """
        Adapter from any Layer1 node-like object.
        """
        return cls(
            node_id=getattr(node, "node_id", getattr(node, "id", "unknown")),
            kind=getattr(node, "kind", "service"),
            meta=getattr(node, "meta", {}),
        )
