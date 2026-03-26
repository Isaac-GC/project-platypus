from dex.clazz import Clazz


class SmaliClazz:
    def __init__(self, class_name):
        self.class_name = class_name
        self.children = [] # Only if there are nested classes

        self.super_class = ""
        self.annotations = []
        self.instance_field = []
        self.static_field = []
        self.methods = []


    def add_child(self, child: Clazz):
        self.children.append(child)
        self.children.sort(key=lambda c: c.name) # Sort by name in alphabetic order



