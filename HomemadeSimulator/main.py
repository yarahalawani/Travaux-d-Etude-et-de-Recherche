import json
import sys
from dataclasses import dataclass
from enum import Enum
import numpy as np

NU = -1

# current : 0 for F, 1 for N, 2 for T, 3 for M
class State(Enum):
    FUNCTIONAL = 0
    NOT_AVAILABLE = 1
    TAINTED = 2
    MALWARE = 3

@dataclass
class Role:
    index: int = 0
    name: str = ""
    protocol: str = ""
    roleType: str = ""
    category: str = ""
    dataBreakCost: int | None = None
    mCodeInjectCost: int | None = None
    bCodeInjectCost: int | None = None
    nCodeInjectCost: int | None = None
    remoteSecrTheftCost = 0
    sessionProtectSecretIndex = []


@dataclass
class Input:
    sourceNodeIndex: int = 0
    debug_sourceNodeName: str = ""
    position: str = ""
    roleIndex: int = 0
    protBreakCostDestruct: int | None = None
    protBreakCostTheft: int | None = None
    protBreakCostTunnelProtocol: int | None = None
    protBreakCostTunnelDecrypt: int | None = None
    protBreakCostTunnelDestroy: int | None = None
    isOpen: str = ""
    tunnelOn: bool = False


@dataclass
class Node:
    current: State = State.FUNCTIONAL
    name: str = ""
    softwareClass: str = ""
    text: str = ""
    kernelIndex: int = 0
    roles = []
    inputs = []
    nodeType: str = ""
    plausThreshold: int = 1
    actThreshold: int = 0
    secrTheftCost: int = 10
    secrStore = []
    monBypassCostToM: int | None = None
    monBypassCostToB: int | None = None
    monBypassCostToN: int | None = None

    def diM(self):
        return len(self.inputs) if len(self.inputs) > 0 else 1

    def diMr(self):
        return len(self.roles) if len(self.roles) > 0 else 1


def minOrNotNone(a, b):
    if a == None:
        return b
    elif b == None:
        return a
    else:
        return min(a, b)

class System:
    nodes: list[Node] = []
    secrets: list[int] = []
    stolenSecrets: list[int] = [False]
    costs = 0 # Coût total jusqu'à présent
    maxCosts = 200 # Total max des coûts
    nbVar = 0 # Nom de secrets

    def getNodeByName(self, node_name) -> Node:
        for node in self.nodes:
            if node.name == node_name:
                return node
        print(f"Nom de noeud inconnu : {node_name}")
        exit(1)

    def reachable(self, node_id, input_id):
        node = self.nodes[node_id]
        inp: Input = node.inputs[input_id]
        tokens = inp.isOpen.split()
        # Structure de isOpen : [Nom noeud] [Opérateur binaire (<> par exemple pour la non égal)] $[État (B, N ou M)] & ...

        # Au cas où la formule est vide
        if len(tokens) <= 0:
            return True
        
        i = 0
        while True:
            if i >= len(tokens):
                print(f"Il manque une expression dans la formule isOpen de l'input {i} du noeud {node.name}")
            i_node_name = tokens[i]
            i_node = self.getNodeByName(i_node_name)
            i+=1
            if i >= len(tokens):
                print(f"Il manque un opérateur binaire dans la formule isOpen de l'input {i} du noeud {node.name}")
                exit(1)
            if tokens[i] != '<>':
                print(f"System.reachable : L'opération {tokens[i]} n'est pas supportée pour le moment")
                exit(1)
            i+=1
            if i >= len(tokens):
                print(f"Il manque la spécification de l'état dans la formule isOpen de l'input {i} du noeud {node.name}")
                exit(1)
            state_str = tokens[i]
            if state_str != '$N':
                print(f"System.reachable : L'état {state_str} est inconnu")
                exit(1)
            if i_node.current == State.NOT_AVAILABLE:
                return False
            i+=1
            if i >= len(tokens):
                break
            if tokens[i] != '&':
                print(f"System.reachable : L'opérateur binaire {tokens[i]} est inconnu")
                exit(1)
            i+=1
        return True

    
    def ProtProtectCost(self, node_id: int, input_id: int, role_id: int, sourceNodeIndex: int, attack_position: str) -> int:
        node = self.nodes[node_id]
        protCost: int | None = node.inputs[input_id].protBreakCostTheft
        tunnCost: int | None = node.inputs[input_id].protBreakCostTunnelProtocol
        keyProtect = False
        kernelSId = self.nodes[sourceNodeIndex].kernelIndex

        for i in range(0, self.nbVar - 1):
            if len(node.roles[role_id].sessionProtectSecretIndex) > 0:
                kerSt = False
                if kernelSId != node_id:
                    kerSt = self.nodes[kernelSId].secrStore[i]

                keyProtect = True
                if (self.stolenSecrets[i] or self.nodes[sourceNodeIndex].secrStore[i] or kerSt):
                    protCost = 0

        if attack_position == 'peer':
            if keyProtect:
                if protCost == None:
                    return NU
                return protCost
            else:
                return 0

        if node.inputs[input_id].tunnelOn:
            if protCost == None or tunnCost == None:
                return NU
            else:
                return protCost + tunnCost
        else:
            if protCost == None:
                return NU
            return protCost

    def ProtDestructCost(self, node_id: int, input_id: int, role_id: int, sourceNodeIndex: int, attack_position: str) -> int:
        node = self.nodes[node_id]
        protCostBr = node.inputs[input_id].protBreakCostDestruct
        protCostBr: int = protCostBr if protCostBr != None else NU
        tunCostBr = node.inputs[input_id].protBreakCostTunnelDestroy
        tunCostBr: int = tunCostBr if tunCostBr != None else NU
        keyProtect = False
        protCost = node.inputs[input_id].protBreakCostTheft
        protCost: int = protCost if protCost != None else NU
        tunCost = node.inputs[input_id].protBreakCostTunnelProtocol
        tunCost: int = tunCost if tunCost != None else NU
        kernelSId = node.kernelIndex

        if protCostBr == None or (protCost != None and protCost < protCostBr):
            protCostBr = protCost

        for i in range(0, self.nbVar):
            if len(node.roles[role_id].sessionProtectSecretIndex):
                kerSt = False
                if kernelSId != node_id:
                    kerSt = node.secrStore[i]
                keyProtect = True
                if self.stolenSecrets[i] or self.nodes[sourceNodeIndex].secrStore[i] or kerSt:
                    protCostBr = 0

        if attack_position == 'peer':
            if keyProtect:
                return protCostBr
            else:
                return 0

        if node.inputs[input_id].tunnelOn:
            if tunCost == NU or protCostBr == NU or (tunCost + protCost > tunCostBr):
                return tunCostBr
            return protCostBr + tunCostBr
        else:
            return protCostBr


    def MinCostMalware(self, node_id: int, target_state: State) -> int:
        node = self.nodes[node_id]
        cost = NU
        tcost = NU
        suppl = 0
        if node.nodeType == "kernel" and target_state == State.TAINTED:
            return NU
        if len(node.inputs) <= 0:
            return NU

        for i in range(0, node.diM()):
            if not self.reachable(node_id, i):
                continue
            
            if ((self.nodes[node.inputs[i].sourceNodeIndex].current == State.MALWARE) or (self.nodes[node.inputs[i].sourceNodeIndex].current == State.TAINTED and node.inputs[i].position == 'peer')):
                role_id = node.inputs[i].roleIndex
                role = node.roles[role_id]
                attack_position = node.inputs[i].position
                tcost = self.ProtProtectCost(node_id, i, role_id, node.inputs[i].sourceNodeIndex,attack_position)

                if target_state == State.TAINTED:
                    if tcost > NU and role.bCodeInjectCost != None:
                        tcost += role.bCodeInjectCost
                    else:
                        tcost = NU
                elif target_state == State.NOT_AVAILABLE:
                    if tcost > NU and role.nCodeInjectCost != None:
                        tcost += role.nCodeInjectCost
                    else:
                        tcost = NU
                elif target_state == State.MALWARE:
                    if tcost > NU and role.mCodeInjectCost != None:
                        tcost += role.mCodeInjectCost
                    else:
                        tcost = NU

                if tcost > NU and (cost == NU or tcost < cost):
                    cost = tcost
            
        if cost <= NU:
            return NU

        cost += suppl
        if ((cost + self.costs) <= self.maxCosts):
            return cost
        else:
            return NU


    def minBadDataCost(self, node_id: int):
        node = self.nodes[node_id]
        rolCostBd = [NU] * node.diMr()
        rolOk: list[bool] = [False] * node.diMr()

        bdCost = 0
        tcost = NU
        tr = 0
        totRolOk = 0
        totRolBd = 0
        mustcompromise = NU
        nbCompr = 0
        activityCost = 0
        tr1 = NU
        j = NU

        if len(node.inputs) <= 0:
            return NU
        if node.nodeType == 'kernel':
            return NU

        for i in range(0, node.diM()):
            if self.reachable(node_id, i) and node.roles[node.inputs[i].roleIndex].roleType != 'system' and node.roles[node.inputs[i].roleIndex].category != 'transparent':
                attackerState = self.nodes[node.inputs[i].sourceNodeIndex].current
                role_id = node.inputs[i].roleIndex
                attack_position = node.inputs[i].position
                costDir = node.roles[role_id].dataBreakCost
                protCost = self.ProtProtectCost(node_id, i, role_id, node.inputs[i].sourceNodeIndex, attack_position)
                tt = NU
                if (protCost == NU or costDir == NU):
                    tt = NU
                else:
                    tt += costDir + protCost
                
                if (tt != NU and (attackerState == State.MALWARE) or (attackerState == State.TAINTED and attack_position == 'peer')):
                    if rolCostBd[role_id] == NU or rolCostBd[role_id] > tt:
                        rolCostBd[role_id] = tt

                if attackerState == State.FUNCTIONAL and attack_position == 'peer':
                    rolOk[role_id] = True

        for role_id in range(0, node.diMr()):
            if node.roles[role_id].roleType == 'system':
                continue

            if node.roles[role_id].category == 'mandatory':
                if rolCostBd[role_id] == NU and not rolOk[role_id]:
                    return NU
                if not rolOk[role_id]:
                    mustcompromise = mustcompromise + rolCostBd[role_id] if mustcompromise > NU else rolCostBd[role_id]
                if tcost == NU or rolCostBd[role_id] < tcost:
                    tcost = rolCostBd[role_id]
            elif node.roles[role_id].category == 'optional':
                totRolOk += 1

        if (mustcompromise > NU) and (totRolOk >= node.actThreshold):
            return mustcompromise

        nbCompr = node.actThreshold - totRolOk
        activityCost = 0
        totRolBd = 0
        
        for k in range(0, node.diMr()):
            if nbCompr <= 0:
                continue

            tr1 = NU
            for role_id in range(0, node.diMr()):
                if (node.roles[role_id].roleType != 'system' and node.roles[role_id].category == 'optional' and rolCostBd[role_id] != None and not rolOk[role_id]):
                    if tr1 == NU or tr1 > rolCostBd[role_id]:
                        tr1 = rolCostBd[role_id]
                        j = role_id
            
            if tr1 != NU:
                nbCompr -= 1
                totRolBd += 1
                activityCost += tr1
                rolCostBd[j] = NU
                totRolOk += 1

        if nbCompr > 0:
            return NU

        if mustcompromise > NU:
            return activityCost + mustcompromise

        nbCompr = node.plausThreshold - totRolBd
        bdCost = NU
        for k in range(0, node.diMr()):
            if nbCompr <= 0:
                continue
            tr1 = NU
            for role_id in range(0, node.diMr()):
                if node.roles[role_id].roleType != 'system' and node.roles[role_id].category == 'optional' and rolCostBd[role_id] and rolOk[role_id]:
                    if tr1 == NU or tr1 > rolCostBd[role_id]:
                        tr1 = rolCostBd[role_id]
                        j = role_id
            if tr1 != NU:
                nbCompr -= 1
                if bdCost != NU:
                    bdCost += tr1
                else:
                    bdCost = tr1
                rolCostBd[j] = NU
        
        if nbCompr > 0 and tcost < 0:
            return NU

        if tcost < 0:
            if bdCost < 0:
                return activityCost
            return activityCost + bdCost

        if bdCost != NU:
            return activityCost + (tcost if tcost < bdCost else bdCost)
        return activityCost + tcost


    def BadData(self, node_id: int):
        suppl = 0
        badDataCost = self.minBadDataCost(node_id)
        if badDataCost == NU:
            return NU
        badDataCost += suppl
        if ((badDataCost + self.costs) <= self.maxCosts):
            return badDataCost
        return NU


    def MinFB(self, node_id: int):
        mal = self.MinCostMalware(node_id, State.TAINTED)
        bd = self.BadData(node_id)
        if mal == NU:
            return bd
        if bd == NU:
            return mal
        if bd > mal:
            return mal
        return bd

    def minNonDispCost(self, node_id: int) -> int:
        node = self.nodes[node_id]
        rolCostBdM = [NU] * node.diMr()
        rolOk = [False] * node.diMr()
        nbOKnMand = 0
        tcost = NU
        nbtocomp = 0
        bdCost = NU
        tr = NU

        if len(node.inputs) <= 0:
            return NU

        for input_id in range(0, node.diM()):
            if self.reachable(node_id, input_id) and (node.roles[node.inputs[input_id].roleIndex].category != 'transparent') and (node.roles[node.inputs[input_id].roleIndex].roleType != 'system'):
                attackerState = self.nodes[node.inputs[input_id].sourceNodeIndex].current
                role_id = node.inputs[input_id].roleIndex
                attack_position = node.inputs[input_id].position
                sessDestruct = NU

                if (attackerState == State.FUNCTIONAL) and (attack_position == 'peer'): 
                    rolOk[role_id] = True

                if rolCostBdM[role_id] != 0:
                    sessDestruct = self.ProtDestructCost(node_id, input_id, role_id, node.inputs[input_id].sourceNodeIndex, attack_position)
                    if sessDestruct != NU:
                        if rolCostBdM[role_id] == NU:
                            rolCostBdM[role_id] = sessDestruct
                        elif sessDestruct < rolCostBdM[role_id]:
                            rolCostBdM[role_id] = sessDestruct 

        for role_id in range(0, node.diMr()):
            if node.roles[role_id].roleType != 'system' and node.roles[role_id].category != 'transparent':
                if node.roles[role_id].category == 'mandatory':
                    if not rolOk[role_id]:
                        return 0
                    if rolCostBdM[role_id] != NU:
                        if (tcost == NU) or (rolCostBdM[role_id] < tcost):
                            tcost = rolCostBdM[role_id]
                elif node.roles[role_id].category == 'optional':
                    if rolOk[role_id]:
                        nbOKnMand += 1

        if nbOKnMand < node.actThreshold:
            return 0

        nbtocomp = 1 + nbOKnMand - node.actThreshold

        for k in range(0, node.diMr()):
            tr1 = NU
            j = NU
            
            for role_id in range(0, node.diMr()):
                if node.roles[role_id].roleType != 'system' and node.roles[role_id].category == 'optional' and rolCostBdM[role_id] != NU and tr < nbtocomp:
                    if (tr1 == NU) or tr1 > rolCostBdM[role_id]:
                        tr1 = rolCostBdM[role_id]
                        j = role_id

            if tr1 != NU:
                tr += 1
                bdCost = (bdCost if (bdCost != NU) else 0) + tr1
                rolCostBdM[j] = NU

        if tr < nbtocomp:
            return tcost

        if tcost == NU:
            return bdCost

        return tcost if (bdCost > tcost) else bdCost

    
    def NoProducerDisp(self, node_id: int):
        suppl = 0
        NoProducerDispCost = self.minNonDispCost(node_id)
        if NoProducerDispCost == NU:
            return NU
        NoProducerDispCost += suppl
        if (NoProducerDispCost + self.costs) <= self.maxCosts:
            return NoProducerDispCost
        return NU

    def MinFN(self, node_id: int) -> int:
        node = self.nodes[node_id]
        mal = self.MinCostMalware(node_id, State.NOT_AVAILABLE)
        noProd = self.NoProducerDisp(node_id)

        if mal == NU:
            return noProd
        if noProd == NU:
            return mal
        if noProd > mal:
            return mal
        return noProd

    def MinFM(self, node_id: int) -> int:
        return self.MinCostMalware(node_id, State.MALWARE)
    
    def RemoteSecrCost(self, node_id: int) -> int:
        node = self.nodes[node_id]
        cost = NU
        tcost = NU
        z = 0
        if len(node.inputs) <= 0:
            return NU
        for i in range(0, self.nbVar):
            if (not self.stolenSecrets[i]) and node.secrStore[i]:
                z+=1
        if z == 0:
            return NU
        
        for i in range(0, node.diM()):
            if self.reachable(node_id, i):
                if self.nodes[node.inputs[i].sourceNodeIndex].current == State.MALWARE:
                    role_id = node.inputs[i].roleIndex
                    attack_position = node.inputs[i].position
                    tcost = self.ProtProtectCost(node_id, i, role_id, node.inputs[i].sourceNodeIndex, attack_position)
                    if tcost > NU and node.roles[role_id].remoteSecrTheftCost != None:
                        tcost += node.roles[role_id].remoteSecrTheftCost
                    else:
                        tcost = NU
                    if tcost > NU:
                        if cost == NU or tcost < cost:
                            cost += tcost

        if cost <= NU:
            return NU
        if cost + self.costs <= self.maxCosts:
            return cost
        else:
            return NU
        
    def setRemoteSecr(self, node_id: int):
        node = self.nodes[node_id]
        for i in range(0, self.nbVar):
            if not self.stolenSecrets[i] and node.secrStore[i]:
                self.stolenSecrets[i] = True


    def LocalVarCost(self, node_id: int):
        node = self.nodes[node_id]
        cost = NU
        for i in range(0, self.nbVar):
            if not self.stolenSecrets[i] and node.secrStore[i]:
                cost = node.secrTheftCost
                if (cost + self.costs) <= self.maxCosts:
                    return cost
                return NU

        return NU

    def setLocalSecr(self, node_id: int):
        node = self.nodes[node_id]
        for i in range(0, self.nbVar):
            if not self.stolenSecrets[i] and node.secrStore[i]:
                self.stolenSecrets[i] = True


    def computeAvailableTransitions(self):
        trans = []

        for node_id in range(0, len(self.nodes)):
            node = self.nodes[node_id]

            if node.current == State.FUNCTIONAL:
                fn = self.MinFN(node_id)
                if fn != NU:
                    trans.append((node_id, State.FUNCTIONAL, State.NOT_AVAILABLE, fn, None))

                ft = self.MinFB(node_id)
                if ft != NU:
                    trans.append((node_id, State.FUNCTIONAL, State.NOT_AVAILABLE, ft, None))

                fm = self.MinFM(node_id)
                if fm != NU:
                    trans.append((node_id, State.FUNCTIONAL, State.MALWARE, fm, None))

                ff = self.RemoteSecrCost(node_id)
                if ff != NU:
                    trans.append((node_id, State.FUNCTIONAL, State.FUNCTIONAL, ff, self.setRemoteSecr))

            elif node.current == State.MALWARE:
                mm = self.LocalVarCost(node_id)
                if mm != NU:
                    trans.append((node_id, State.MALWARE, State.MALWARE, mm, self.setLocalSecr))
            
        return trans


def loadSystemFromJSON(file_name: str):
    f = open(file_name)

    data = json.load(f)

    system = System()

    system.nbVar = data['nbSecrets']
    system.stolenSecrets = [False] * system.nbVar

    for n in data['nodes']:
        node = Node()

        node.current = State(n['current'] if ('current' in n) else 0)
        node.name = n['name']
        node.softwareClass = n['softwareClass']
        node.text = n['text']
        node.kernelIndex = n['kernelIndex']
        node.nodeType = n['nodeType']
        node.secrStore = n['secrStore']
        if len(node.secrStore) != system.nbVar:
            node.secrStore = [False] * system.nbVar
        node.monBypassCostToM = n['monBypassCost']['toM']
        node.monBypassCostToB = n['monBypassCost']['toB']
        node.monBypassCostToN = n['monBypassCost']['toN']

        node.roles = []

        roleIndex = 0
        
        for r in n['roles']:
            role = Role(index=roleIndex, name=r['name'], protocol=r['protocol'], roleType=r['type'],
                        category=r['categ'])

            role.dataBreakCost = r['dataBreakCost']
            role.mCodeInjectCost = r['mCodeInjectCost']
            role.bCodeInjectCost = r['bCodeInjectCost']
            role.nCodeInjectCost = r['nCodeInjectCost']
            role.remoteSecrTheftCost = r['remoteSecrTheftCost']
            role.sessionProtectSecretIndex = r['sessionProtectSecretIndex']

            node.roles.append(role)

            roleIndex += 1

        node.inputs = []

        for i in n['inputs']:
            input = Input(sourceNodeIndex=i['sourceNodeIndex'], debug_sourceNodeName=i['debug_sourceNodeName'],
                          position=i['position'], roleIndex=i['roleIndex'], isOpen=i['isOpen'])

            input.protBreakCostDestruct = i['protBreakCosts']['destruct']
            input.protBreakCostTheft = i['protBreakCosts']['theft']
            input.protBreakCostTunnelProtocol = i['protBreakCosts']['tunnelProtocol']
            input.protBreakCostTunnelDecrypt = i['protBreakCosts']['tunnelDecrypt']
            input.protBreakCostTunnelDestroy = i['protBreakCosts']['tunnelDestroy']

            node.inputs.append(input)

        node.plausThreshold = n['plausThreshold']
        node.actThreshold = n['actThreshold']
        node.secrTheftCost = n['secrTheftCost']
        node.secrStore = n['secrStore']

        system.nodes.append(node)

    return system


def calculateReward(system: System):
    score = 0 
    for node in system.nodes:
        if node.current == State.NOT_AVAILABLE:
            score += 1
        elif node.current == State.TAINTED:
            score += 1.5
        elif node.current == State.MALWARE:
            score += 2

    return score


def encodeState(system: System):
    # encodage pour les états : chaque noeud sur 2 bits : 00 pour F, 01 pour T, 10 pour N et 11 pour M 
    sid = 0
    for i, node in enumerate(system.nodes):
        if node.current == State.TAINTED:
            sid += 1 * (4 ** i)
        elif node.current == State.NOT_AVAILABLE:
            sid += 2 * (4 ** i)
        elif node.current == State.MALWARE:
            sid += 3 * (4 ** i)
    return sid

def encodeAction(transition):
    node_index = transition[0]
    if transition[1] == State.FUNCTIONAL: # curr_state == F 
        if transition[2] == State.FUNCTIONAL: # FF 
            return 5 * node_index
        elif transition[2] == State.TAINTED:
            return 1 + (5 * node_index)
        elif transition[2] == State.NOT_AVAILABLE:
            return 2 + (5 * node_index)
        elif transition[2] == State.MALWARE:
            return 3 + (5 * node_index)
    elif transition[1] == State.MALWARE:
        if transition[2] == State.MALWARE:
            return 4 + (5 * node_index)
        
    pass
    
import copy

def q_learn(initial_state: System, max_cost = 150, learning_rate = 0.8, discount_factor = 0.95, exploration_prob = 0.2, epochs = 10000):
    n_states = 4 ** len(initial_state.nodes)
    n_actions = 5 * len(initial_state.nodes)

    Q_table = np.zeros((n_states, n_actions))

    for epoch in range(epochs):
        current_state = copy.deepcopy(initial_state)
        current_state.nodes = copy.deepcopy(initial_state.nodes)
        current_state.secrets = copy.deepcopy(initial_state.secrets)
        current_state.stolenSecrets = copy.deepcopy(initial_state.stolenSecrets)
        cost = 0
        chosenActions = []

        while cost <= max_cost:        
            sid = encodeState(current_state)

            availableTransitions = current_state.computeAvailableTransitions()
            
            if len(availableTransitions) == 0:
                break

            encodedActions = []

            for trans in availableTransitions:
                encodedActions.append(encodeAction(trans))

            action = 0
            max_action = 0
            max_qvalue = Q_table[sid][encodedActions[0]]

            if np.random.rand() < exploration_prob:
                action = np.random.randint(0, len(availableTransitions))
            else:
                for i, encodedAction in enumerate(encodedActions):
                    q_val = Q_table[sid][encodedAction]
                    if max_qvalue > q_val:
                        max_qvalue = q_val 
                        max_action = i
                action = max_action
            
            chosenAction = availableTransitions[action]
            chosenActions.append(chosenAction)
            current_state.nodes[chosenAction[0]].current = chosenAction[2]
            cost += chosenAction[3]
            if chosenAction[4] != None:
                chosenAction[4](chosenAction[0])

            reward = calculateReward(current_state)

            Q_table[sid,encodedActions[action]] += learning_rate * (reward + discount_factor * np.max(Q_table[encodeState(current_state)]) - Q_table[sid,encodedActions[action]])

    return Q_table

def printBestStrategy(initial_state: System, Q_table: np.array, max_cost: int = 150):
    cost = 0

    current_state = copy.deepcopy(initial_state)
    current_state.nodes = copy.deepcopy(initial_state.nodes)
    current_state.secrets = copy.deepcopy(initial_state.secrets)
    current_state.stolenSecrets = copy.deepcopy(initial_state.stolenSecrets)

    while cost < max_cost:
        cost = 0

        sid = encodeState(current_state)

        availableTransitions = current_state.computeAvailableTransitions()

        if len(availableTransitions) == 0:
            break

        encodedActions = []

        for trans in availableTransitions:
            encodedActions.append(encodeAction(trans))

        max_action = 0
        max_qvalue = Q_table[sid][encodedActions[0]]

        for i, encodedAction in enumerate(encodedActions):
            q_val = Q_table[sid][encodedAction]
            print(q_val)
            if max_qvalue > q_val:
                max_qvalue = q_val 
                max_action = i

        chosenAction = availableTransitions[max_action]
        current_state.nodes[chosenAction[0]].current = chosenAction[2]
        cost += chosenAction[3]
        if chosenAction[4] != None:
            chosenAction[4](chosenAction[0])

        print(f"Transition effectuée : noeud {current_state.nodes[chosenAction[0]].name}, de {chosenAction[1]} vers {chosenAction[2]} pour un coût de {chosenAction[3]}")
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage : python3 main.py FICHIER_JSON")
        exit(0)
    system: System = loadSystemFromJSON(sys.argv[1])
    totalCost: int = 0

    q_table = q_learn(system)

    printBestStrategy(system, q_table)

    exit(0)
