import angr
import claripy

base = 0x08048000
after_input = 0x08048622
check = 0x08048669
user_input = 0x0804a050
enc_password = "AUPDNNPROEZRJWKB"

p = angr.Project("08_angr_constraints", main_opts={"base_addr":base})
state = p.factory.blank_state(addr=after_input)

password = claripy.BVS("p", 16*8)
state.memory.store(user_input, password)

simgr = p.factory.simulation_manager(state)
simgr.explore(find=check)

for found in simgr.found:
    enc_input = found.memory.load(user_input, 16)
    found.solver.add(enc_input == enc_password)
    
    print(found.solver.eval(password, cast_to=bytes))