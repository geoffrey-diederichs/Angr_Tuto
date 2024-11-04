import angr

base_addr = 0x08048000
win = 0x080485dd
loose = 0x080485a8

p = angr.Project("01_angr_avoid", auto_load_libs=False, main_opts={"base_addr":base_addr})

state = p.factory.entry_state()

simgr = p.factory.simulation_manager(state)
simgr.explore(find=win, avoid=loose)

for found in simgr.found:
    print(found.posix.dumps(0))