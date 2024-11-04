import angr
import claripy

base_addr = 0x08048000
after_input_addr = 0x08048694
win = 0x080486e1
loose = 0x080486cf

p = angr.Project("04_angr_symbolic_stack", main_opts={"base_addr":base_addr})

state = p.factory.blank_state(addr=after_input_addr)

password_len = 4*8
password_1 = claripy.BVS("p1", password_len)
password_2 = claripy.BVS("p2", password_len)

stack = state.regs.ebp
state.mem[stack-0xc].uint32_t = password_1
state.mem[stack-0x10].uint32_t = password_2

simgr = p.factory.simulation_manager(state)
simgr.explore(find=win, avoid=loose)

for found in simgr.found:
    print(f"{found.solver.eval(password_1)} {found.solver.eval(password_2)}")
