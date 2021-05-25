#include "arch.h"

#include <algorithm>
#include <array>

// SP points to the first argument that is passed on the stack
#define ARG0_STACK 0

namespace bpftrace {
namespace arch {

// clang-format off
static std::array<std::string, 18> registers = {
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "fp",
  "ip",
  "sp",
  "lr",
  "pc",
  "cpsr",
  "orig_r0",
};

// Alternative register names that match struct pt_regs
static std::array<std::string, 18> ptrace_registers = {
  "uregs[0]",
  "uregs[1]",
  "uregs[2]",
  "uregs[3]",
  "uregs[4]",
  "uregs[5]",
  "uregs[6]",
  "uregs[7]",
  "uregs[8]",
  "uregs[9]",
  "uregs[10]",
  "uregs[11]",
  "uregs[12]",
  "uregs[13]",
  "uregs[14]",
  "uregs[15]",
  "uregs[16]",
  "uregs[17]",
};

static std::array<std::string, 4> arg_registers = {
  "r0",
  "r1",
  "r2",
  "r3",
};
// clang-format on

int offset(std::string reg_name)
{
  auto it = find(registers.begin(), registers.end(), reg_name);
  if (it == registers.end())
  {
    // Also allow register names that match the fields in struct pt_regs.
    // These appear in USDT probe arguments.
    it = find(ptrace_registers.begin(), ptrace_registers.end(), reg_name);
    if (it == ptrace_registers.end())
      return -1;
    return distance(ptrace_registers.begin(), it);
  }
  return distance(registers.begin(), it);
}

int max_arg()
{
  return arg_registers.size() - 1;
}

int arg_offset(int arg_num)
{
  return offset(arg_registers.at(arg_num));
}

int ret_offset()
{
  return offset("lr");
}

int pc_offset()
{
  return offset("pc");
}

int sp_offset()
{
  return offset("sp");
}

int arg_stack_offset()
{
  return ARG0_STACK / 8;
}

std::string name()
{
  return std::string("arm");
}

std::vector<std::string> invalid_watchpoint_modes()
{
  // See arch/arm/kernel/hw_breakpoint.c:arch_build_bp_info in kernel source
  return std::vector<std::string>{
    "rx",
    "wx",
    "rwx",
  };
}

} // namespace arch
} // namespace bpftrace
