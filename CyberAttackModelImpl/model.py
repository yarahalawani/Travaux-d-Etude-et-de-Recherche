from hyena import ena, Annotated, F
from hyena.ena import *

@dataclass 
class Node(ena.Node):
    name: Annotated[str, F.UNIQUE("System")] 

@dataclass 
class System(ena.System):
    pass
