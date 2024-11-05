import angr
import claripy

base_addr = 0x08048000
after_input_addr = 0x080488e7
win = 0x080489ad
loose = 0x08048993

buffer = 0x0804a0a0
filename = "OJKSQYDP.txt"

p = angr.Project("07_angr_symbolic_file", main_opts={"base_addr":base_addr})
state = p.factory.blank_state(addr=after_input_addr)

password = claripy.BVS("p", 64*8)
file = angr.SimFile(filename, content=password, size=64*8)
state.fs.insert(filename, file)

simgr = p.factory.simulation_manager(state)
simgr.explore(find=win, avoid=loose)

for found in simgr.found:
    print(found.solver.eval(password, cast_to=bytes))