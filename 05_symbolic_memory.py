import angr
import claripy

base_addr = 0x08048000
after_input_adrr = 0x080485fe
win = 0x0804866a
loose = 0x08048658

password_1_addr = 0x0a1ba1c0
password_2_addr = 0x0a1ba1c8
password_3_addr = 0x0a1ba1d0
password_4_addr = 0x0a1ba1d8

p = angr.Project("05_angr_symbolic_memory", main_opts={"base_addr":base_addr})

state = p.factory.blank_state(addr=after_input_adrr)

password_len = 8*8
password_1 = claripy.BVS("p1", password_len)
password_2 = claripy.BVS("p2", password_len)
password_3 = claripy.BVS("p3", password_len)
password_4 = claripy.BVS("p4", password_len)

state.memory.store(password_1_addr, password_1)
state.memory.store(password_2_addr, password_2)
state.memory.store(password_3_addr, password_3)
state.memory.store(password_4_addr, password_4)

simgr = p.factory.simulation_manager(state)
simgr.explore(find=win, avoid=loose)

for found in simgr.found:
    print(f"{found.solver.eval(password_1, cast_to=bytes).decode()} {found.solver.eval(password_2, cast_to=bytes).decode()} {found.solver.eval(password_3, cast_to=bytes).decode()} {found.solver.eval(password_4, cast_to=bytes).decode()}")