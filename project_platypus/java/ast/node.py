import pickle


class MetaNode(type):
    def __new__(mcs, name, bases, dict):
        attrs = list(dict['attrs'])
        dict['attrs'] = list()

        for base in bases:
            if hasattr(base, 'attrs'):
                dict['attrs'].extend(base.attrs)

        dict['attrs'].extend(attrs)

        return type.__new__(mcs, name, bases, dict)


class Node(object, metaclass=MetaNode):
    attrs = ()

    def __init__(self, **kwargs):
        values = kwargs.copy()

        for attr_name in self.attrs:
            value = values.pop(attr_name, None)
            setattr(self, attr_name, value)

        if values:
            raise ValueError("Extraneous arguments in 'values'")


    def __eq__(self, other):
        if type(other) is not type(self):
            return False

        for attr_name in self.attrs:
            if getattr(self, attr_name) != getattr(other, attr_name):
                return False

        return True

    def __equals__(self, other):
        return self.__eq__(other)

    def __repr__(self):
        attr_values = []
        for attr_name in sorted(self.attrs):
            attr_values.append(f"{attr_name}={getattr(self, attr_name)}")

        return f"{type(self).__name__}({', '.join(attr_values)})"

    def __iter__(self):
        return walk_tree(self)

    def filter(self, pattern):
        for path, node in self:
            if ((isinstance(pattern, type) and isinstance(node, pattern)) or (node == pattern)):
                yield path, node

    @property
    def children(self):
        return [getattr(self, attr_name) for attr_name in self.attrs]

    @property
    def position(self):
        if hasattr(self, '_position'):
            return self._position
        return None


## Tree-walking Logic
def walk_tree(root):
    children = None

    if isinstance(root, Node):
        yield (), root
        children = root.children
    else:
        children = root

    for child in children:
        if isinstance(child, (Node, list, tuple)):
            for path, node in walk_tree(child):
                yield (root, ) + path, node


## Helper Functions
def dump(ast, file):
    pickle.dump(ast, file)

def load(file):
    return pickle.load(file)