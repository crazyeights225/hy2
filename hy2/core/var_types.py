class VInst:
    def __init__(self, v):
        self.v = v
    
    def __eq__(self, other):
        if type(other) == int and type(self.v) == int:
            return self.v == other
        elif type(other) == VInst:
            return self.v == other.v
        
        return False

    def __sub__(self, other):
        if type(other) == int:
            return self.v - other

        if type(other) == VInst:
            return self.v - other.v

    def __hash__(self) -> int:
        return hash(self.v)

    def __repr__(self) -> str:
        return str(self.v)

class VRange:
    def __init__(self, start, stop, step):
        self.start = start
        self.stop = stop
        self.step = step

    def __eq__(self, other):
        if type(other) == VRange:
            return self.start == other.start and self.stop == other.stop and self.step == other.step
        return False
    
    def __repr__(self):
        return f'range({self.start}, {self.stop}, {self.step})'
    
    def __hash__(self) -> int:
        return hash(str(self))
    
class VSet:
    def __init__(self, vals):
        self.vals = vals
    
    def __repr__(self):
        return str(self.vals)

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other):
        if type(other) == VSet:
            return self.vals == other.vals
        return False

class VRepr:
    def __init__(self, v):
        self.v = v
    
    def __hash__(self) -> int:
        return hash(str(self))

    def __sub__(self, other):
        if type(other) == int:
            return self.v - other

        if type(other) == VInst:
            return self.v - other.v

    def __repr__(self):
        return f'repr({self.v})'

class VEmpty:
    def __init__(self):
        pass

    def __hash__(self):
        return hash("VEmpty")
    
    def __repr__(self) -> str:
        return "VEmpty"
