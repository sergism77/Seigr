from datetime import datetime, timezone

class AccessControlManager:
    def __init__(self, creator_id):
        self.creator_id = creator_id
        self.acl = [{"user_id": "default", "role": "viewer", "permissions": "read"}]
        self.access_context = {"access_count": 0, "last_accessed": "", "node_access_history": []}

    def record_access(self, node_id):
        self.access_context["access_count"] += 1
        self.access_context["last_accessed"] = datetime.now(timezone.utc).isoformat()
        self.access_context["node_access_history"].append(node_id)
