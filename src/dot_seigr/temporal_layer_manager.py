from datetime import datetime, timezone

class TemporalLayerManager:
    def __init__(self, index):
        self.index = index
        self.layers = []

    def add_layer(self, metadata, data):
        timestamp = datetime.now(timezone.utc).isoformat()
        self.layers.append({
            "timestamp": timestamp,
            "layer_hash": metadata["segment_hash"],
            "data_snapshot": {str(self.index): data}
        })
