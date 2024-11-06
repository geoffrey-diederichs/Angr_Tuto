import angr
import claripy

base = 0x08048000

def solve_first_password() -> bytes:
    after_input = 0x08048662
    after_input_enc = 0x080486a9
    user_input = 0x0804a054
    first_password_enc = "XYMKBKUHNIQYNQXE"

    state = p.factory.blank_state(addr=after_input)

    input = claripy.BVS("p", 16*8)
    state.memory.store(user_input, input)

    simgr = p.factory.simulation_manager(state)
    simgr.explore(find=after_input_enc)

    for found in simgr.found:
        enc_input = found.memory.load(user_input, 16)
        found.solver.add(enc_input == first_password_enc)
        return found.solver.eval(input, cast_to=bytes)
    return b""

def solver_second_password() -> bytes:
    after_check = 0x080486b8
    after_passw_enc = 0x08048700
    passw = 0x0804a044

    state = p.factory.blank_state(addr=after_check)
    enc_passw = claripy.BVV(b"XYMKBKUHNIQYNQXEXYMKBKUHNIQYNQXE", 32*8)
    state.memory.store(passw, enc_passw)

    simgr = p.factory.simulation_manager(state)
    simgr.explore(find=after_passw_enc)

    for found in simgr.found:
        decr_passw = found.memory.load(passw, 16)
        return found.solver.eval(decr_passw, cast_to=bytes)
    return b""
    

if __name__ == "__main__":
    p = angr.Project("09_angr_hooks", main_opts={"base_addr":base})
    first_password = solve_first_password()
    second_password = solver_second_password()

    print(f"First password : {first_password}\nSecond password : {second_password}")