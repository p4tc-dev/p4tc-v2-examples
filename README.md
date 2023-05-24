# P4TC Examples

This repository aims to provide simple examples to help users better understand
P4TC and how to use it. To better understand P4TC, please take a look at the
[P4TC doc](https://github.com/p4tc-dev/docs/blob/main/why-p4tc.md).

## Models

In this new P4TC RFC patch (RFC V2), we are providing users with 3 usage models
for P4TC.

### Model1

The first model uses an eBPF program as the P4TC program's parser, and maintains
the other components using the P4TC commands.

In the directory *model1*, we show examples of programs that use 1 and 2 tables.
These examples are under subdirectory *model1/1table* and *model1/2tables*.
We further divide these examples by table match kind, which are *exact*, *LPM*,
and *ternary*. So, in directory *model1/1table/exact* we have all the scripts
necessary to load our P4TC program that does *exact* match. The program in
question has a table called *nh_table* whose key is an *IPv4* source address.
When the lookup in *nh_table* matches, the program calls action *send_nh* which
will rewrite the packet's source and destination mac address and redirect it to
a network port. The parser extracts the packet's *ethernet* and *IPv4* headers.
Below we list all files in *model1/1table/exact/* and their purpose:

- redirect\_l2\_pna\_1t\_exact.p4: The P4 program
- redirect\_l2\_pna\_1t\_exact\_parser.c: The eBPF C parser code
- redirect\_l2\_pna\_1t\_exact.template: The P4TC template which expresses the
  P4 program (except the parser) using the P4TC commands
- redirect\_l2\_pna\_1t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it (along with its parser) to a TC P4 filter
- redirect\_l2\_pna\_1t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it to a TC P4 filter. This time we bind the parser to XDP, instead of
  the TC P4 filter

In the directory *model1/1table/lpm* we have the same program, but with a
different match kind. In the directory *model1/1table/ternary*, we have almost
the same program, but the key for *nh_table* is the *source and destination*
IPv4 addresses, and the match kind is *ternary*.

In the directory *model1/2tables/exact* we have a similar example as the one
above. However this time we have 2 tables. The first table (*nh_table1*) is
looked up using the source IPv4 address as a key. Its match kind is exact.
After parsing, the P4TC program performs a table apply in *nh_table1*. If we
match, we execute action accept. If we don't match we execute action
default\_drop. Action *accept* sets a boolean user defined metadata called
*accept*. *default_drop* calls extern *drop_packet*. After the table apply for
*nh_table1* has been done, the program checks user metadata *accept*. If it is
*true*, we proceed to a table apply of the second table (*nh_table2*).
*nh_table2* has as its key the IPv4 destination address. Its match kind is also
exact. If we match the lookup of *nh_table2*, we execute action *send_nh*, which
will rewrite the packet's source and destination mac address and redirect it to
a specific network port. Below we list all files in *model1/2tables/exact/* and
their purpose:

- redirect\_l2\_pna\_2t\_exact.p4: The P4 program
- redirect\_l2\_pna\_2t\_exact\_parser.c: The eBPF C parser code
- redirect\_l2\_pna\_2t\_exact.template: The P4TC template which expresses the
  P4 program (except the parser) using the P4TC commands
- redirect\_l2\_pna\_2t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it (along with its parser) to a TC P4 filter
- redirect\_l2\_pna\_1t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it to a TC P4 filter. This time we bind the parser to XDP, instead of
  the TC P4 filter

In the directory *model1/2tables/lpm* we have the same program, but with a
different match kind. In the directory *model1/1table/ternary*, we have almost
the same program, but the key for *nh_table1* is the *source and destination*
IPv4 addresses, the key for *nh_table2* is the *destination and source* IPv4
addresses and the match kind is *ternary*.

### Model2

The second model uses a single eBPF program to represent the P4TC data path.
In this version we don't use the P4TC commands, however we maintain
the P4TC infrastructure for the control path operations.

In the directory *model2*, we show programs that use 1 and 2 tables.
These examples are under subdirectory *model2/1table* and *model2/2tables*.
We further divide these examples by table match kind, which are *exact*, *LPM*,
and *ternary*. So, in directory *model2/1table/exact* we have all the scripts
necessary to load our P4TC program that does *exact* match. The program in
question has a table called *nh_table* whose key is an *IPv4* source address.
When the lookup in *nh_table* matches, the program calls action *send_nh* which
will rewrite the packet's source and destination mac address and redirect it to
a network port. The parser extracts the packet's *ethernet* and *IPv4* headers.
Below we list all files in *model2/1table/exact/* and their purpose:

- redirect\_l2\_pna\_1t\_exact.p4: The P4 program
- redirect\_l2\_pna\_1t\_exact.c: The eBPF C code corresponding to the P4 program
- redirect\_l2\_pna\_1t\_exact.template: The P4TC template which expresses the
  the template components of the P4 program (such as tables and actions).
- redirect\_l2\_pna\_1t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it (along with its parser) to a TC P4 filter
- redirect\_l2\_pna\_1t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it to a TC P4 filter. This time we bind the parser to XDP, instead of
  the TC P4 filter

In directory *model2/1table/lpm* we have the same program, but with a different
match kind. In the directory *model2/1table/ternary*, we have almost the same
program, but the key for *nh_table* is the *source and destination* IPv4
addresses, and the match kind for both is *ternary*.

In the directory *model2/2tables/exact* we have a similar example as the one
above. However this time we have 2 tables. The first table (*nh_table1*) is
looked up using the source IPv4 address as a key. Its match kind is exact.
After parsing, the P4TC program performs a table apply in *nh_table1*. If we
match, we execute action accept. If we don't match, we execute action
default\_drop. Actions *accept* sets a boolean user defined metadata called
*accept*. *default_drop* calls extern *drop_packet*. After the table apply for
*nh_table1* has been done, the program checks user metadata *accept*. If it is
*true*, we proceed to a table apply of the second table (*nh_table2*).
*nh_table2* has as its key the IPv4 destination address. Its match kind is also
exact. If we match the lookup of *nh_table2*, we execute action *send_nh*, which
will rewrite the packet's source and destination mac address and redirect it to
a specific network port. Below we list all files in *model2/2tables/exact/* and
their purpose:

- redirect\_l2\_pna\_2t\_exact.p4: The P4 program
- redirect\_l2\_pna\_2t\_exact.c: The eBPF C code corresponding to the P4 program
- redirect\_l2\_pna\_2t\_exact.template: The P4TC template which expresses the
  template components of the P4 program (such as tables and actions).
- redirect\_l2\_pna\_2t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it (along with its parser) to a TC P4 filter
- redirect\_l2\_pna\_2t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it to a TC P4 filter. This time we bind the parser to XDP, instead of
  the TC P4 filter

In the directory *model2/2tables/lpm* we have the same program, but with a
different match kind. In the directory *model2/1table/ternary*, we have almost
the same program, but the key for *nh_table1* is the *source and destination*
IPv4 addresses, the key for *nh_table2* is the *destination and source* IPv4
addresses and the match kind for both is *ternary*.

### Model2 with separate parser

The second model uses an eBPF program to represent the P4 parser and another
eBPF program which represents the remaining components of the P4 program.
In this version we don't use the P4TC commands, however we maintain the P4TC
infrastructure for the control path operations.

In the directory *model2_sep_parser*, we show examples of programs that use 1
and 2 tables. These examples are under subdirectory *model2_sep_parser/1table*
and *model2_sep_parser/2tables*. We further divide these examples by table match
kind, which are *exact*, *LPM*, and *ternary*. So, in directory
*model2_sep_parser/1table/exact* we have all the scripts necessary to load our
P4TC program that does *exact* match. The program in question has a table called
*nh_table* whose key is an *IPv4* source address. When the lookup in *nh_table*
matches, the program calls action *send_nh* which will rewrite the packet's
source and destination mac address and redirect it to a network port. The parser
extracts the packet's *ethernet* and *IPv4* headers. Below we list all files in
*model2_sep_parser/1table/exact/* and their purpose:

- redirect\_l2\_pna\_1t\_exact.p4: The P4 program
- redirect\_l2\_pna\_1t\_exact\_parser.c: The eBPF C code corresponding to the
  the P4 program's parser
- redirect\_l2\_pna\_1t\_exact\_noparser.c: The eBPF C code corresponding to the
  the remaining components of the P4 program
- redirect\_l2\_pna\_1t\_exact.template: The P4TC template which expresses the
  template components of the P4 program (such as tables and actions)
- redirect\_l2\_pna\_1t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it (along with its parser) to a TC P4 filter
- redirect\_l2\_pna\_1t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it to a TC P4 filter. This time we bind the parser to XDP, instead of
  the TC P4 filter

In the directory *model2_sep_parser/1table/lpm* we have the same program, but
with a different match kind. In the directory
*model2_sep_parser/1table/ternary*, we have almost the same program, but the key
for *nh_table* is the *source and destination* IPv4 addresses, and the match
kind is *ternary*.

In the directory *model2_sep_parser/2tables/exact* we have a similar example as
the one above. However this time we have 2 tables. The first table (*nh_table1*)
is looked up using the source IPv4 address as a key. Its match kind is exact.
After parsing, the P4TC program performs a table apply in *nh_table1*. If we
match, we execute action accept. If we don't match we execute action
default\_drop. Actions *accept* sets a boolean user defined metadata called
*accept*. *default_drop* calls extern *drop_packet*. After the table apply for
*nh_table1*has been done, the program checks user metadata *accept*. If it is
*true*, we proceed to a table apply of the second table (*nh_table2*).
*nh_table2* has as its key the IPv4 destination address. Its match kind is also
exact. If we match the lookup of *nh_table2*, we execute action *send_nh*, which
will rewrite the packet's source and destination mac address and redirect it to
a specific network port. Below we list all files in
*model2_sep_parser/2tables/exact/* and their purpose:

- redirect\_l2\_pna\_2t\_exact.p4: The P4 program
- redirect\_l2\_pna\_2t\_exact\_parser.c: The eBPF C code corresponding to the
  the P4 program's parser
- redirect\_l2\_pna\_2t\_exact\_noparser.c: The eBPF C code corresponding to the
  the remaining components of the P4 program
- redirect\_l2\_pna\_2t\_exact.template: The P4TC template expresses
  the template components of the P4 program (such as tables and actions)
- redirect\_l2\_pna\_2t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it (along with its parser) to a TC P4 filter
- redirect\_l2\_pna\_2t\_exact\_tc.runtime: Script to load the P4TC program
  and bind it to a TC P4 filter. This time we bind the parser to XDP, instead of
  the TC P4 filter

In the directory *model2_sep_parser/2tables/lpm* we have the same program, but
with a different match kind. In the directory
*model2_sep_parser/1table/ternary*, we have almost the same program, but the key
for is *nh_table1* is the *source and destination* IPv4 addresses, the key for
*nh_table2* is the *destination and source* IPv4 addresses and the match kind
for both is *ternary*.

## Compilation

To compile any of the eBPF C programs, the user needs to have LLVM (15+), with
clang and llc, installed.  We also need to install libbpf-dev, libelf-dev and
gcc-multilib. To install these in ubuntu, one could issue the following command:


apt install clang-15 libbpf-dev gcc-multilib --install-suggests

We have a Makefile which takes care of compilation.
Before invoking it the user must specify the path to the eBPF program they wish
to compile. For example, to compile redirect\_l2\_pna\_2t\_exact\_noparser.c
from model2 with a separate parser, the user should issue the following commands:

make model2\_sep\_parser/2tables/exact/redirect\_l2\_pna\_2t\_exact\_noparser.o

If we simply run *make* without arguments, the Makefile will compile all of the
eBPF C programs from all models (model1, model2, model2\_sep\_parser).

You can also tell the Makefile to compile only the files form one model, for
example:

make model2
