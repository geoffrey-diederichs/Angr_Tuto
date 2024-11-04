import angr
import claripy

base_addr = 0x08048000
after_input_addr = 0x08048696
win = 0x08048756
loose = 0x08048744

fake_addr = 0xdeadbeef
password_1_addr = 0x0abcc8a4
password_2_addr = 0x0abcc8ac

p = angr.Project("06_angr_symbolic_dynamic_memory", main_opts={"base_addr":base_addr})

state = p.factory.blank_state(addr=after_input_addr)

password_len = 8*8
password_1 = claripy.BVS("p1", password_len)
password_2 = claripy.BVS("p2", password_len)

state.mem[password_1_addr].uint32_t = fake_addr
state.mem[password_2_addr].uint32_t = fake_addr+8

state.memory.store(fake_addr, password_1)
state.memory.store(fake_addr+8, password_2)

simgr = p.factory.simulation_manager(state)
simgr.explore(find=win, avoid=loose)

for found in simgr.found:
    print(f"{found.solver.eval(password_1, cast_to=bytes).decode()} {found.solver.eval(password_2, cast_to=bytes).decode()}")
