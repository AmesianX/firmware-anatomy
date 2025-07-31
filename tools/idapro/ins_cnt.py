import idaapi, idautils, idc

mnemonic = "bkpt"
count = 0

# iterate all code items in all segments
for seg in idautils.Segments():
    for ea in idautils.Heads(seg, idc.get_segm_end(seg)):
        if idc.print_insn_mnem(ea).lower() == mnemonic:
            count += 1

print("{} instructions found: {}".format(mnemonic.upper(), count))
