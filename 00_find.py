import angr
import claripy

base_addr = 0x08048000
win = 0x08048675
loose = 0x08048663

p = angr.Project("00_angr_find", auto_load_libs=False, main_opts={"base_addr":base_addr})

state = p.factory.entry_state()

simgr = p.factory.simulation_manager(state)
simgr.explore(find=win, avoid=loose)

for found in simgr.found:
    print(found.posix.dumps(0))
