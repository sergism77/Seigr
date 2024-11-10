class LinkManager:
    def __init__(self):
        self.links = {"primary": None, "secondary": []}

    def set_links(self, primary, secondary):
        self.links["primary"] = primary
        self.links["secondary"] = secondary
