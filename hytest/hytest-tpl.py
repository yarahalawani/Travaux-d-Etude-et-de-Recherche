from hyena import Template

class Transition(Template):
    cost = 42
    def action(self):
        if self.sameloc():
            return 0
        else:
            return self.cost

    def sameloc(self):
        idx = node.inputs[0].node
        return node.current == system.nodes[idx].current
