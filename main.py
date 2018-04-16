import angr
import subprocess

sensitive_functions = (
    'setuid',
    'setgid'
)


def parse_args():
    import argparse

    arg_parser = argparse.ArgumentParser(description='Find potential threats for sensitive system functions.')
    arg_parser.add_argument('binary', metavar='BINARY', type=str, nargs=1)
    return arg_parser.parse_args()


def get_all_addresses(program, cfg):
    process = subprocess.Popen(['objdump', '-dl', program], stdout=subprocess.PIPE)
    out, err = process.communicate()
    import re
    pattern = '([0-9a-f]+):' \
              '(\s*[0-9a-f][0-9a-f])+' \
              '\s*callq\s*[0-9a-f]+\s*<(%s)@plt>' % '|'.join(sensitive_functions)
    matched = re.findall(pattern, out)

    # return the address in the matched results
    return tuple((int(match[0], 16), match[2]) for match in matched)


def main():
    args = parse_args()

    project = angr.Project(args.binary[0], load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGAccurate(keep_state=True, enable_symbolic_back_traversal=True)

    state = project.factory.entry_state()
    #sm = project.factory.simulation_manager(state)

    sensitive_calls = get_all_addresses(args.binary[0], cfg)

    # dumb! don't know how to continue execution after found a state
    # https://docs.angr.io/docs/pathgroups.html#simple-exploration says it CAN, but doesn't say HOW
    for (address, function_name) in sensitive_calls:
        sm = project.factory.simulation_manager(state)
        sm.explore(find=address, num_find=5)
        if len(sm.found) > 0:

            # check if the call will always be triggered
            will_always_trigger = False
            for found in sm.found:
                if ord(found.posix.dumps(0)[0]) == 1:
                    will_always_trigger = True

            # output warning
            if not will_always_trigger:
                print("Warning! Input \'%s\' will trigger (0x%x, %s)" % (sm.found[0].posix.dumps(0), address, function_name))
        else:
            print("No paths found in %x, %s" % (address, function_name))


if __name__ == '__main__':
    main()
