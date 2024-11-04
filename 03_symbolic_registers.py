import angr
import claripy

base_addr = 0x08048000
after_input_addr = 0x08048980
win = 0x080489e6
loose = 0x080489d4

def hex_to_ascii(raw:int) -> str:
    return bytes.fromhex(hex(raw)[2:]).decode('ascii')

p = angr.Project("03_angr_symbolic_registers", main_opts={"base_addr":base_addr})

state = p.factory.blank_state(addr=after_input_addr)

pass_len = 32 # Size of registers in bits
passw_1 = claripy.BVS("p1", pass_len)
passw_2 = claripy.BVS("p2", pass_len)
passw_3 = claripy.BVS("p3", pass_len)

state.regs.eax = passw_1
state.regs.ebx = passw_2
state.regs.edx = passw_3

simgr = p.factory.simulation_manager(state)
simgr.explore(find=win, avoid=loose)

for found in simgr.found:
    print(f"{hex(found.solver.eval(passw_1))} {hex(found.solver.eval(passw_2))} {hex(found.solver.eval(passw_3))}")
