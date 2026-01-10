


class Clazz:
    def __init__(self, class_name):
        self.class_name = class_name
        self.children = [] # Only if there are nested classes

        self.super_class = ""
        self.annotations = []
        self.instance_field = []
        self.static_field = []
