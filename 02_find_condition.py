import angr

def win_condition(state) -> bool:
    return b"Good Job." in state.posix.dumps(1)

def loose_condition(state) -> bool:
    return b"Try again." in state.posix.dumps(1)

p = angr.Project("02_angr_find_condition", auto_load_libs=False)

state = p.factory.entry_state()

simgr = p.factory.simulation_manager(state)
simgr.explore(find=win_condition, avoid=loose_condition)

for found in simgr.found:
    print(found.posix.dumps(0))