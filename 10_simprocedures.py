import angr
import claripy

BASE = 0x08048000

def solve(p) -> bytes:
    after_input = 0x080486c0
    passwd_addr = 0x0804c048
    passwd = claripy.BVV(b"ORSDDWXHZURJRBDH", 16*8)
    passwd_addr = 0x0804c048

    class check_equals(angr.SimProcedure):
        def run(self, enc_input_addr, length):
            enc_input = self.state.memory.load(enc_input_addr, length)
            return claripy.If(
                passwd == enc_input,
                claripy.BVV(1, 4*8), 
                claripy.BVV(0, 4*8)
            )

    def win(state) -> bool:
        return b"Good Job." in state.posix.dumps(1)
    
    def loose(state) -> bool:
        return b"Try again." in state.posix.dumps(1)
    
    p.hook_symbol("check_equals_ORSDDWXHZURJRBDH", check_equals())

    state = p.factory.blank_state(addr=after_input)

    input = claripy.BVS("i", 16*8)
    input_addr = state.regs.ebp-0x1d
    state.memory.store(input_addr, input)

    simgr = p.factory.simulation_manager(state)
    simgr.explore(find=win, avoid=loose)

    for found in simgr.found:
        return found.solver.eval(input, cast_to=bytes)
    return b""

if __name__ == "__main__":
    p = angr.Project("10_angr_simprocedures", main_opts={"base_addr":BASE})
    password = solve(p)

    print(f"Password : {password}")