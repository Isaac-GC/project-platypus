

class CallGraph:

    def __init__(self):
        self.nodes = {}
        self.starting_node = None

    def set_starting_node(self, node_name: str):
        pass

    # def process_node(self, node_ref: ):


class Node:
    def __init__(self):
        self.name = ""
        self.reference = None
        self.edges = []

class Edge:
    def __init__(self):
        self.source = None
        self.destination = None