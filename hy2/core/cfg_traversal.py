#--------------------------------------
# File: cfg_traversal.py
#
# Purpose: Helper functions for traversing CFG model for checker
#--------------------------------------

# Multi-threading:
# initial state match - locate matching states in thread model
# successor states:
#  - find successors in thread model
# traversal:
#  - find successors in thread model
# - check state where sid0 != sid1
#  - keep track of callstack

# check by state (cfg), find successors by thread model
# ie. traversal state (tuple of states) not the same as check state
# only check the state in the active thread (sid0 != sid1)

class TraversalDepthException(Exception):
    def __init__(self, depth, message="Exception: Expected Traversal Depth Exceeded"):
        self.depth = depth
        self.message = message
        super().__init__(self.message)
    
    def __str__(self):
        return f'{self.message}: Depth {self.depth}'

def get_next_model_state(model, a0):
    return [t.dest for t in model.get_transitions(source=a0)]

def get_previous_model_state(model, a0):
    return [t.source for t in model.get_transitions(dest=a0)]

def update_callstack(call_stack, actions):
    for action in actions:
        if action[0] == "insert":
            elem = action[1]
            idx = call_stack.index(elem)
            tid = call_stack[idx][1]
            call_stack = call_stack[:idx] + [(0,tid)] + call_stack[idx:] 
        elif action[0] == "drop":
            elem = action[1]
            idx = call_stack.index(elem)
            call_stack = call_stack[:idx] + call_stack[idx+1:]
            print('dropping')
            print(call_stack)
            
        elif action[0] == 'nothing':
                pass  
        elif action[0] == "push":
            call_stack = [action[1]] + call_stack
        else:
            call_stack = call_stack[1:]
    
    return call_stack

# call_stack - one stack per thread, entries are (return_addr, hit)
# The inner lists are replaced rather than modified, so a shallow copy of
# call_stack is enough to keep the caller's stacks intact.
def update_callstack_concur(call_stack, actions):
    for action in actions:
        if action[0] == "nothing":
            continue
        tidx = action[1][0] if action[0] == "push" else action[1]
        while len(call_stack) <= tidx:
            call_stack.append([])
        if action[0] == "push":
            call_stack[tidx] = [(action[1][1],0)] + call_stack[tidx]
        elif action[0] == "pop":
            call_stack[tidx] = call_stack[tidx][1:]
        elif action[0] == "hit":
            # thread returned but was switched out before reaching the return address
            if len(call_stack[tidx]) > 0:
                call_stack[tidx] = [(call_stack[tidx][0][0], 1)] + call_stack[tidx][1:]
    return call_stack

# model - program model
# labels - backing nodes
# s0 - current state
# call_stack 
def get_successor_states(model, labels, s0, call_stack):
    next_states = get_next_model_state(model, s0) 
    if len(next_states) == 0:
            print("[!] ERROR: No next states")
            return next_states, []
    new_next_states = []
    actions = []

    m0 = labels[s0]
    pop_check = False
    peek_check = False
    peek = None
    if len(call_stack) > 0:
        peek = call_stack[0]
        pop_check = m0.transition.transition_type == "Ijk_Ret" or (m0.transition.transition_type == "Ijk_Boring" and len(m0.invocations) > 0)
        if type(m0.transition.dest_pc) == int:
            peek_check = peek == m0.transition.dest_pc
        else:
            peek_check = peek in m0.transition.dest_pc
        
    for s1 in next_states:
        if not s1 in labels and s0 != s1:
            actions += [[("nothing", 0)]]
            new_next_states += [s1]
            continue
            
        m1 = labels[s1]
            
        # If next state == current state, skip, we don't want to get stuck in an infinite loop
        if s0 == s1:
            continue

        if pop_check:
            if not peek == m1.pc and peek != 0:
                continue
            actions += [[("pop", 0)]]
            new_next_states += [s1]
        elif peek_check:
            if peek == m1.pc or peek == 0:
                actions += [[("pop", 0)]]
                new_next_states += [s1]
            else:
                continue  
        elif m0.transition.transition_type == "Ijk_Call":
            assert labels[s0].return_addr != m1.pc
            assert type(labels[s0].return_addr) == int
            if m1.transition.transition_type == "Ijk_Call" and m1.return_addr == m0.return_addr:
                # I have no idea why this happened :/
                actions += [[("nothing", 0)]]
            else:
                actions += [[("push", (labels[s0].return_addr))]]
            new_next_states += [s1]
        else:
            actions += [[("nothing", 0)]]
            new_next_states += [s1]
    
    return new_next_states, actions

def get_active_thread(current_state, next_state):
    if len(current_state) < len(next_state):
        return len(next_state) - 1
    idxs =  [i for i in range(len(next_state)) if current_state[i] != next_state[i]]
    assert len(idxs) == 1
    return idxs[0]

def get_successor_states_concur(thread_graph, labels, active_thread, s0, call_stack):
    next_states = get_next_model_state(thread_graph, s0)
    if len(next_states) == 0:
        return next_states, [], []

    new_next_states = []
    new_active_threads = []
    actions = []

    t0 = thread_graph.states[s0].label
    st0 = t0[active_thread]
    m0 = labels[st0]

    pop_check = False
    peek_check = False
    peek = None

    if len(call_stack) > active_thread and len(call_stack[active_thread]) > 0:
        peek = call_stack[active_thread][0][0]
        pop_check = m0.transition.transition_type == "Ijk_Ret" or (m0.transition.transition_type == "Ijk_Boring" and len(m0.invocations) > 0)
        if type(m0.transition.dest_pc) == int:
            peek_check = peek == m0.transition.dest_pc
        else:
            peek_check = peek in m0.transition.dest_pc

    for s1 in next_states:
        if s0 == s1:
            continue
        t1 = thread_graph.states[s1].label
        # the active thread did not move, so another thread was scheduled
        thread_switch = active_thread >= len(t1) or st0 == t1[active_thread]
        if not thread_switch:
            st1 = thread_graph.states[s1].label[active_thread]
            if not st1 in labels and not st0 == st1:
                actions += [[("nothing", 0)]]
                new_next_states += [s1]
                new_active_threads += [active_thread]
                continue
            
            m1 = labels[st1]
            
            if pop_check:
                if not peek == m1.pc and peek != 0:
                    continue
                actions += [[("pop", active_thread)]]
                new_next_states += [s1]
                new_active_threads += [active_thread]
            elif peek_check:
                if peek == m1.pc or peek == 0:
                    actions += [[("pop", active_thread)]]
                    new_next_states += [s1]
                    new_active_threads += [active_thread]
                else:
                    continue
            elif m0.transition.transition_type == "Ijk_Call":
                assert m0.return_addr != m1.pc
                assert type(m0.return_addr) == int
                if m1.transition.transition_type == "Ijk_Call" and m1.return_addr == m0.return_addr:
                    # I have no idea why this happened :/
                    actions += [[("nothing", 0)]]
                else:
                    actions += [[("push", (active_thread, m0.return_addr))]]
                new_next_states += [s1]
                new_active_threads += [active_thread]
            else:
                actions += [[("nothing", 0)]]
                new_next_states += [s1]
                new_active_threads += [active_thread]
        else:
            new_active_thread = get_active_thread(t0, t1)
            peek0 = call_stack[new_active_thread] if new_active_thread < len(call_stack) else []
            st1 = t1[new_active_thread]
            if not st1 in labels:
                actions += [[("nothing", 0)]]
                new_next_states += [s1]
                new_active_threads += [new_active_thread]
                continue
            m1 = labels[st1]
            s1_actions = []
            if pop_check:
                s1_actions += [("hit", active_thread)]
            if len(peek0) > 0 and peek0[0][0] == m1.pc:
                s1_actions += [("pop", new_active_thread)]
            elif len(peek0) > 0 and peek0[0][1] == 1 and peek0[0][0] != m1.pc:
                continue

            if m0.transition.transition_type == "Ijk_Call":
                assert type(m0.return_addr) == int
                if m1.transition.transition_type == "Ijk_Call" and m1.return_addr == m0.return_addr:
                    # I have no idea why this happened :/
                    s1_actions += [("nothing", 0)]
                else:
                    s1_actions += [("push", (active_thread, m0.return_addr))]
            if len(s1_actions) == 0:
                s1_actions += [("nothing", 0)]
            actions += [s1_actions]
            new_next_states += [s1]
            new_active_threads += [new_active_thread]
    
    return new_next_states, new_active_threads, actions
    

def queryStateInThreadModel(graph, state):
    idxs = []
    states =  []
    for k,v in graph.states.items():
        if state in v.label:
            idx = v.label.index(state)
            states += [k]
            idxs += [idx]
    
    return states, idxs